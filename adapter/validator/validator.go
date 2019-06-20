// Package validator provides structures responsible for validating tokens according to custom policies
package validator

import (
	"fmt"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

const (
	kid = "kid"
	aud = "aud"
)

// TokenValidator parses and validates JWT tokens according to policies
type TokenValidator interface {
	Validate(token string, jwks keyset.KeySet, rules []v1.Rule) *errors.OAuthError
}

// Validator implements the TokenValidator
type Validator struct{}

// RawTokens - holds references to raw access and id tokens
// empty tokens are represented with ""
type RawTokens struct {
	Access string
	ID     string
}

////////////////// constructor //////////////////

// New creates a New TokenValidator
func New() TokenValidator {
	return &Validator{}
}

////////////////// interface //////////////////////////

// Validate validates tokens according to the specified policies.
// If any policy fails, the entire request should be rejected
func (*Validator) Validate(tokenStr string, jwks keyset.KeySet, rules []v1.Rule) *errors.OAuthError {

	if tokenStr == "" {
		zap.L().Debug("Unauthorized - Token does not exist")
		return errors.UnauthorizedHTTPException("token not provided", nil)
	}

	if jwks == nil {
		zap.L().Debug("Unauthorized - JWKS not provided")
		return &errors.OAuthError{
			Msg: errors.InternalServerError,
		}
	}
	// Parse the access token - validate expiration and signature
	token, err := validateSignature(tokenStr, jwks)
	if err != nil {
		zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
		return errors.UnauthorizedHTTPException(err.Error(), nil)
	}

	// Validate access token
	claimErr := validateClaims(token, rules)
	if claimErr != nil {
		zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
		return errors.UnauthorizedHTTPException(claimErr.Msg, nil)
	}

	zap.L().Debug("Token has been validated")

	return nil
}

////////////////// utils //////////////////////////

// validateSignature parses the given token and verifies the ExpiresAt, NotBefore, and signature
func validateSignature(token string, jwks keyset.KeySet) (*jwt.Token, error) {

	// Method used by token library to get public key for signature validation
	getKey := func(token *jwt.Token) (interface{}, error) {

		// Validate token signature against
		keyID, ok := token.Header[kid].(string)
		if keyID == "" || !ok {
			zap.L().Debug("Token validation error - kid is missing")
			return nil, fmt.Errorf("token validation error - kid is missing")
		}

		// Find public key in client
		key := jwks.PublicKey(keyID)
		if key == nil {
			zap.L().Debug("Token validation error - key not found", zap.String("kid", token.Header[kid].(string)))
			return nil, fmt.Errorf("token validation error - key not found :: %s", token.Header[kid])
		}

		return key, nil
	}

	return jwt.Parse(token, getKey)
}

// validateClaims validates claims based on policies
func validateClaims(token *jwt.Token, rules []v1.Rule) *errors.OAuthError {
	if token == nil {
		zap.L().Error("Unexpectedly received nil token during validation")
		return &errors.OAuthError{Msg: errors.InternalServerError}
	}

	// Retrieve claims map from token
	claims, err := getClaims(token)
	if err != nil {
		zap.L().Warn("Token validation error - error obtaining claims from token")
		return err
	}

	for _, rule := range rules {
		if err := checkAccessPolicy(rule, claims); err != nil {
			return &errors.OAuthError{
				Code: errors.InvalidToken,
				Msg:  err.Error(),
			}
		}
	}

	return nil
}

// checkAccessPolicy is used to validate a specific claim with the claims map
func checkAccessPolicy(rule v1.Rule, claims jwt.MapClaims) error {
	m, err := convertClaimType(claims[rule.Claim])
	if err != nil {
		zap.L().Info("Could not convert claim", zap.Error(err), zap.String("claim_name", rule.Claim))
		return err
	}
	switch rule.Match {
	case "ANY":
		return validateClaimMatchesAny(rule.Claim, m, rule.Value)
	case "NOT":
		return validateClaimDoesNotMatch(rule.Claim, m, rule.Value)
	default: // "ALL"
		return validateClaimMatchesAll(rule.Claim, m, rule.Value)
	}
}

func validateClaimMatchesAny(name string, claims map[string]struct{}, expected []string) error {
	for _, c := range expected {
		if _, ok := claims[c]; ok {
			return nil
		}
	}
	return fmt.Errorf("token validation error - expected claim `%s` to match one of: %s", name, expected)
}

func validateClaimMatchesAll(name string, claims map[string]struct{}, expected []string) error {
	if len(expected) == 0 {
		return fmt.Errorf("token validation error - expected claim `%s` to match all of: %s, but is empty", name, expected)
	}
	for _, c := range expected {
		if _, ok := claims[c]; !ok {
			return fmt.Errorf("token validation error - expected claim `%s` to match all of: %s", name, expected)
		}
	}
	return nil
}

func validateClaimDoesNotMatch(name string, claims map[string]struct{}, expected []string) error {
	for _, c := range expected {
		if _, ok := claims[c]; ok {
			return fmt.Errorf("token validation error - expected claim `%s` to not match any of: %s", name, expected)
		}
	}
	return nil
}

func convertClaimType(value interface{}) (map[string]struct{}, error) {
	m := map[string]struct{}{}
	switch t := value.(type) {
	case nil:
		return m, nil
	case bool:
		m[strconv.FormatBool(t)] = struct{}{}
		return m, nil
	case []bool:
		for _, v := range t {
			m[strconv.FormatBool(v)] = struct{}{}
		}
		return m, nil
	case int:
		m[string(t)] = struct{}{}
		return m, nil
	case []int:
		for _, v := range t {
			m[string(v)] = struct{}{}
		}
		return m, nil
	case string:
		for _, v := range strings.Split(t, " ") {
			m[v] = struct{}{}
		}
		return m, nil
	case []string:

		return m, nil
	case []interface{}:
		for _, v := range t {
			switch s2 := v.(type) {
			case string:
				m[s2] = struct{}{}
			case int:
				m[string(s2)] = struct{}{}
			case bool:
				m[strconv.FormatBool(s2)] = struct{}{}
			default:
				return nil, fmt.Errorf("claim is not of a supported type: %s", s2)
			}
		}
		return m, nil
	default:
		return nil, fmt.Errorf("claim is not of a supported type: %s", t)
	}
}

// getClaims retrieves claims map from JWT
func getClaims(token *jwt.Token) (jwt.MapClaims, *errors.OAuthError) {
	if token != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return claims, nil
		}
	}
	zap.L().Debug("Token validation error - invalid JWT token")
	return nil, &errors.OAuthError{Msg: errors.InvalidToken}
}

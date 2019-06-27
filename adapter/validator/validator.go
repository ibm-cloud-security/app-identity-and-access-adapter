// Package validator provides structures responsible for validating tokens according to custom policies
package validator

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go/v4"
	"go.uber.org/zap"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

const (
	kid   = "kid"
	scope = "scope"
	NOT   = "NOT"
	ANY   = "ANY"
)

// TokenValidator parses and validates JWT tokens according to policies
type TokenValidator interface {
	Validate(token string, tokenType Token, jwks keyset.KeySet, rules []v1.Rule, userInfoEndpoint string) *errors.OAuthError
}

// Validator implements the TokenValidator
type Validator struct{}

// OidcTokenValidator implements the TokenValidator
type OidcTokenValidator struct{}

// JwtTokenValidator implements the TokenValidator
type JwtTokenValidator struct{}

// RawTokens - holds references to raw access and id tokens
// empty tokens are represented with ""
type RawTokens struct {
	Access string
	ID     string
}

// //////////////// constructor //////////////////

// New creates a New TokenValidator
func NewTokenValidator(policyType policy.Type) TokenValidator {
	switch policyType {
	case policy.OIDC:
		return &OidcTokenValidator{}
	case policy.JWT:
		return &JwtTokenValidator{}
	default:
		return nil
	}
}

// //////////////// interface //////////////////////////

// Validate validates tokens according to the specified policies.
// If any policy fails, the entire request should be rejected
func (o *OidcTokenValidator) Validate(tokenStr string, tokenType Token, jwks keyset.KeySet, rules []v1.Rule, userInfoEndpoint string) *errors.OAuthError {

	if tokenStr == "" {
		zap.L().Debug("Unauthorized - Token does not exist")
		return errors.UnauthorizedHTTPException("token not provided", findRequiredScopes(rules))
	}

	if jwks == nil {
		zap.L().Debug("Unauthorized - JWKS not provided")
		return &errors.OAuthError{
			Msg: errors.InternalServerError,
		}
	}

	if jwtFormat := checkJwtFormat(tokenStr); !jwtFormat {
		// token contains an invalid number of segments
		if tokenType == Access {
			return validateAccessTokenString(userInfoEndpoint, tokenStr, rules)
		} else {
			err := errors.UnauthorizedHTTPException("token contains an invalid number of segments", findRequiredScopes(rules))
			zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
			return err
		}
	}

	// Parse the token - validate expiration and signature
	token, err := validateSignature(tokenStr, jwks)
	if err != nil {
		if tokenType != Access {
			zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
			return errors.UnauthorizedHTTPException(err.Error(), findRequiredScopes(rules))
		}
		// if access token plain contains of 3 dots
		return validateAccessTokenString(userInfoEndpoint, tokenStr, rules)
	}

	// Validate token
	claimErr := validateClaims(token, tokenType, rules)
	if claimErr != nil {
		zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
		return errors.UnauthorizedHTTPException(claimErr.Msg, findRequiredScopes(rules))
	}
	zap.L().Debug("Token has been validated")

	return nil
}

// Validate validates tokens according to the specified policies.
// If any policy fails, the entire request should be rejected
func (*JwtTokenValidator) Validate(tokenStr string, tokenType Token, jwks keyset.KeySet, rules []v1.Rule, userInfoEndpoint string) *errors.OAuthError {

	if tokenStr == "" {
		zap.L().Debug("Unauthorized - Token does not exist")
		return errors.UnauthorizedHTTPException("token not provided", findRequiredScopes(rules))
	}

	if jwks == nil {
		zap.L().Debug("Unauthorized - JWKS not provided")
		return &errors.OAuthError{
			Msg: errors.InternalServerError,
		}
	}

	// Parse the token - validate expiration and signature
	token, err := validateSignature(tokenStr, jwks)
	if err != nil {
		zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
		return errors.UnauthorizedHTTPException(err.Error(), findRequiredScopes(rules))
	}

	// Validate token
	claimErr := validateClaims(token, tokenType, rules)
	if claimErr != nil {
		zap.L().Debug("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
		return errors.UnauthorizedHTTPException(claimErr.Msg, findRequiredScopes(rules))
	}
	zap.L().Debug("Token has been validated")

	return nil
}

// //////////////// utilities //////////////////

// validateAccessTokenString validates the access token string
func validateAccessTokenString(userInfoEndpoint string, tokenStr string, rules []v1.Rule) *errors.OAuthError {
	client := &http.Client{}
	req, err := http.NewRequest("GET", userInfoEndpoint, nil)

	if err != nil {
		zap.L().Warn("Failed to get the userinfo", zap.String("url", userInfoEndpoint))
		return errors.BadRequestHTTPException(err.Error())
	}

	req.Header.Set("Authorization", "Basic "+tokenStr)
	if res, err := client.Do(req); err != nil || res.StatusCode != http.StatusOK {
		zap.L().Warn("Unauthorized - invalid token", zap.String("token", tokenStr), zap.Error(err))
		return errors.UnauthorizedHTTPException(err.Error(), findRequiredScopes(rules))
	}

	for _, rule := range rules {
		if rule.Source == Access.String() {
			zap.L().Warn("Unauthorized - rules configured for opaque access token")
			return errors.BadRequestHTTPException("Unauthorized - rules configured for opaque access token")
		}
	}

	return nil
}

// Find scopes returns the required scope rules to return in www-authenticate header
func findRequiredScopes(rules []v1.Rule) []string {
	for _, r := range rules {
		if r.Claim == scope {
			return r.Values
		}
	}
	return nil
}

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
func validateClaims(token *jwt.Token, tokenType Token, rules []v1.Rule) *errors.OAuthError {
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
		if (rule.Source == tokenType.String()) || (rule.Source == "" && Access.String() == tokenType.String()) {
			if err := checkAccessPolicy(rule, claims); err != nil {
				return errors.UnauthorizedHTTPException(err.Error(), nil)
			}
		}
	}

	return nil
}

// checkAccessPolicy is used to validate a specific claim with the claims map
func checkAccessPolicy(rule v1.Rule, claims jwt.MapClaims) error {
	m, err := convertClaimType(getNestedClaim(rule.Claim, claims))
	if err != nil {
		zap.L().Info("Could not convert claim", zap.Error(err), zap.String("claim_name", rule.Claim))
		return err
	}
	switch rule.Match {
	case ANY:
		return validateClaimMatchesAny(rule.Claim, m, rule.Values)
	case NOT:
		return validateClaimDoesNotMatch(rule.Claim, m, rule.Values)
	default: // "ALL"
		return validateClaimMatchesAll(rule.Claim, m, rule.Values)
	}
}

func getNestedClaim(claim string, claims jwt.MapClaims) interface{} {
	tiers := strings.Split(claim, ".")
	for i, tier := range tiers {
		if claim, ok := claims[tier]; ok {
			if i == len(tiers)-1 {
				return claim
			}

			if cast, ok := claim.(map[string]interface{}); ok {
				claims = cast
				continue
			}
			return nil
		}
		return nil
	}

	return nil
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
	if len(claims) == 0 {
		return fmt.Errorf("token validation error - expected claim `%s` does not exist - rule requires: %s", name, expected)
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
	case float64:
		m[strconv.FormatFloat(t, 'f', 0, 64)] = struct{}{}
		return m, nil
	case string:
		for _, v := range strings.Split(t, " ") {
			m[v] = struct{}{}
		}
		return m, nil
	case []interface{}:
		for _, v := range t {
			switch s2 := v.(type) {
			case string:
				m[s2] = struct{}{}
			case float64:
				m[strconv.FormatFloat(s2, 'f', 0, 64)] = struct{}{}
			case bool:
				m[strconv.FormatBool(s2)] = struct{}{}
			default:
				return nil, fmt.Errorf("claim is not of a supported type: %T", s2)
			}
		}
		return m, nil
	default:
		return nil, fmt.Errorf("claim is not of a supported type: %T", t)
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
	return nil, errors.UnauthorizedHTTPException(errors.InvalidToken, nil)
}

// checkJwtFormat : checks the token string for valid jwt format
func checkJwtFormat(token string) bool {
	tokenParts := strings.Split(token, ".")
	return len(tokenParts) == 3
}

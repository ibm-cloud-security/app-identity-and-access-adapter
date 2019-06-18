// Package validator provides structures responsible for validating tokens according to custom policies
package validator

import (
	"fmt"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"go.uber.org/zap"
)

const (
	kid = "kid"
	aud = "aud"
)

// TokenValidator parses and validates JWT tokens according to policies
type TokenValidator interface {
	Validate(token string, jwks keyset.KeySet, rules []policy.Rule) *errors.OAuthError
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
func (*Validator) Validate(tokenStr string, jwks keyset.KeySet, rules []policy.Rule) *errors.OAuthError {

	if tokenStr == "" {
		zap.L().Debug("Unauthorized - Token does not exist")
		return &errors.OAuthError{Msg: errors.InvalidToken}
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
		return claimErr
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
func validateClaims(token *jwt.Token, rules []policy.Rule) *errors.OAuthError {
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
		if err := validateClaim(rule.Key, rule.Value, claims); err != nil {
			return &errors.OAuthError{
				Code: errors.InvalidToken,
				Msg:  err.Error(),
			}
		}
	}

	return nil
}

// validateClaim is used to validate a specific claim with the claims map
func validateClaim(name string, expected string, claims jwt.MapClaims) error {
	switch name {
	case aud:
		if !claims.VerifyAudience(expected, true) {
			zap.L().Debug("token validation error - could not validate claim", zap.String("claim_name", name), zap.String("expected_claim_name", name))
			return fmt.Errorf("token validation error - expected claim `%s` to be %s", name, expected)
		}
	default:
		if found, ok := claims[name].(string); ok {
			if found != expected {
				zap.L().Debug("Token validation error - claim invalid", zap.String("claim_name", name), zap.String("expected", expected), zap.String("found", found))
				return fmt.Errorf("token validation error - expected claim %s to equal %s, but found %s", name, expected, found)
			}
			zap.L().Debug("Validated token claim", zap.String("claim_name", name))
			return nil
		}
		zap.L().Debug("Token validation error - expected claim to exist", zap.String("claim_name", name))
		return fmt.Errorf("token validation error - expected claim `%s` to exist", name)
	}
	return nil
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

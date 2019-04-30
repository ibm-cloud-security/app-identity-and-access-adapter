package validator

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"ibmcloudappid/adapter/authserver/keyset"
	"ibmcloudappid/adapter/errors"
	"istio.io/istio/pkg/log"
)

const (
	kid    = "kid"
	tenant = "tenant"
)

// TokenValidator parses and validates JWT tokens
type TokenValidator interface {
	Validate(token string, jwks keyset.KeySet) *errors.OAuthError
}

// Validator implements the TokenValidator
type Validator struct{}

////////////////// constructor //////////////////

// New creates a New TokenValidator
func New() TokenValidator {
	return &Validator{}
}

////////////////// interface //////////////////////////

// parse parses the given token and verifies the ExpiresAt, NotBefore, and signature
func (*Validator) parse(token string, jwks keyset.KeySet) (*jwt.Token, error) {
	log.Debugf("Parsing token: %s", token)

	// Method used by token library to get public key for signature validation
	getKey := func(token *jwt.Token) (interface{}, error) {

		// Validate token signature against
		keyID, ok := token.Header[kid].(string)
		if keyID == "" || !ok {
			log.Debug("Token validation error - kid is missing")
			return nil, fmt.Errorf("token validation error - kid is missing")
		}

		// Find public key in client
		key := jwks.PublicKey(keyID)
		if key == nil {
			log.Debugf("Token validation error - key not found for kid: %s", token.Header[kid])
			return nil, fmt.Errorf("token validation error - key not found for kid: %s", token.Header[kid])
		}

		return key, nil
	}

	return jwt.Parse(token, getKey)
}

// Validate validates a given JWT's signature, expiration, and given claims
func (parser *Validator) Validate(token string, jwks keyset.KeySet) *errors.OAuthError {
	log.Debugf("Validating token: %s", token)

	// Parse the token - validate expiration and signature
	tkn, err := parser.parse(token, jwks)

	// Check if base token is valid.
	if err != nil {
		return errors.UnauthorizedHTTPException(err.Error(), nil)
	}

	// Retreive claims map from token
	_, ok := getClaims(tkn)
	if !ok {
		log.Debug("Token validation error - error obtaining claims from token")
		return errors.UnauthorizedHTTPException("token validation error - error obtaining claims from token", nil)
	}

	// Validate Rules

	return nil

}

////////////////// utils //////////////////////////

// validateClaim given claim
func validateClaim(name string, expected string, claims jwt.MapClaims) error {
	if found, ok := claims[name].(string); ok {
		if found != expected {
			log.Debugf("Token validation error - expected claim %s to equal %s, but found %s", name, expected, found)
			return fmt.Errorf("token validation error - expected claim %s to equal %s, but found %s", name, expected, found)
		}
		log.Debugf("Validated token claim: `%s`", name)
		return nil
	}
	log.Debugf("Token validation error - expected claim `%s` to exist", name)
	return fmt.Errorf("token validation error - expected claim `%s` to exist", name)
}

// getClaims retrieves claims map from JWT
func getClaims(token *jwt.Token) (jwt.MapClaims, bool) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	}
	log.Debugf("Token validation error - invalid JWT token: %v", token)
	return nil, false
}

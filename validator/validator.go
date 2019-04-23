package validator

import (
	"errors"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/pkg/log"
)

// TokenValidator parses and validates JWT tokens
type TokenValidator interface {
	Validate(client client.Client, token string) error
}

// Validator implements the TokenValidator
type Validator struct{}

////////////////// constructor //////////////////////////

// New creates a New TokenValidator
func New() TokenValidator {
	return &Validator{}
}

////////////////// interface //////////////////////////

// Parse parses the given token
// The underlying Parse function already verifies the ExpiresAt and NotBefore claims
func (*Validator) parse(client client.Client, token string) (*jwt.Token, error) {
	log.Debugf("Parsing token %s", token)

	// Method used by token library to get public key for signature validation
	getKey := func(token *jwt.Token) (interface{}, error) {
		// Validate token signature against
		kid, ok := token.Header["kid"].(string)
		if kid == "" || !ok {
			log.Debug("Token validation error - kid is missing")
			return nil, fmt.Errorf("token validation error - kid is missing")
		}

		// Find public key in client
		pubkeys := client.KeyUtil.PublicKeys()
		pk := pubkeys[kid]
		if pk == nil {
			log.Debugf("Token validation error - key not found for kid: %s", token.Header["kid"])
			return nil, fmt.Errorf("token validation error - key not found for kid: %s", token.Header["kid"])
		}
		return pk, nil
	}

	return jwt.Parse(token, getKey)
}

// Validate validates a given JWT's signature, expiration, and given claims
func (parser *Validator) Validate(client client.Client, token string) error {
	// Parse the token, and validate expiration, and clientID
	log.Debugf("Validating token %s", token)
	tkn, err := parser.parse(client, token)

	// Check if base token is valid.
	if err != nil {
		return err
	}

	// Retreive claims map from token
	claims, ok := getClaims(tkn)
	if ok != true {
		log.Debug("Token validation error - error obtaining claims from token")
		return errors.New("token validation error - error obtaining claims from token")
	}

	// Validate Policies - currently only tenant ID
	if err := validateClaim("tenant", client.Name, claims); err != nil {
		return err
	}

	return nil

}

////////////////// utils //////////////////////////

// validateClaim given claim
func validateClaim(name string, expected string, claims jwt.MapClaims) error {
	if found, ok := claims[name].(string); ok {
		if found != expected { // Validate Tenant ID
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

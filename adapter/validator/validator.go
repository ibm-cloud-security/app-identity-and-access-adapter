package validator

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"ibmcloudappid/adapter/authserver/keyset"
	"ibmcloudappid/adapter/errors"
	"ibmcloudappid/adapter/policy/handler"
	"istio.io/istio/pkg/log"
)

const (
	kid    = "kid"
	tenant = "tenant"
)

// TokenValidator parses and validates JWT tokens
type TokenValidator interface {
	Validate(tokens RawTokens, policies []handler.PolicyAction) *errors.OAuthError
}

// Validator implements the TokenValidator
type Validator struct{}

// RawTokens - holds references to raw access and id tokens
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

// Validate validates tokens according to the specified policies
func (*Validator) Validate(tokens RawTokens, policies []handler.PolicyAction) *errors.OAuthError {
	seenSet := make(map[string]struct{})

	var accessToken *jwt.Token
	var idToken *jwt.Token
	var err error

	for _, p := range policies {
		if p.KeySet == nil {
			log.Error("Internal Server Error: Missing policy keyset")
			return &errors.OAuthError{Msg: errors.InternalServerError}
		}

		// only validate signature for new endpoints
		if _, ok := seenSet[p.KeySet.PublicKeyURL()]; !ok {
			if len(seenSet) == 1 {
				log.Warn("Conflicting policies: requesting signature validation against multiple authorization servers.")
			}
			// Parse the access token - validate expiration and signature
			accessToken, err = validateSignature(tokens.Access, p.KeySet)
			if err != nil {
				return errors.UnauthorizedHTTPException(err.Error(), nil)
			}

			// Parse the id token - validate expiration and signature
			if tokens.ID != "" {
				idToken, err = validateSignature(tokens.ID, p.KeySet)
				if err != nil {
					return errors.UnauthorizedHTTPException(err.Error(), nil)
				}
			}

			seenSet[p.KeySet.PublicKeyURL()] = struct{}{}
		}

		// Validate access token
		err := validateClaims(accessToken)
		if err != nil {
			log.Debugf("Unauthorized - invalid access token - %s", err)
			return err
		}

		// If necessary, validate ID token
		if tokens.ID != "" {
			err = validateClaims(idToken)
			if err != nil {
				log.Debugf("Unauthorized - invalid ID token : %s", err)
				return err
			}
		}
	}

	log.Debug("Authorized")

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

// validateClaims validates claims based on policies
func validateClaims(token *jwt.Token) *errors.OAuthError {
	if token == nil {
		log.Error("Unexpectantly received nil token during validation")
		return &errors.OAuthError{Msg: errors.InternalServerError}
	}

	// Retreive claims map from token
	_, err := getClaims(token)
	if err != nil {
		log.Debug("Token validation error - error obtaining claims from token")
		return err
	}
	// Validate Rules
	return nil
}

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
func getClaims(token *jwt.Token) (jwt.MapClaims, *errors.OAuthError) {
	if token != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return claims, nil
		}
	}
	log.Debugf("Token validation error - invalid JWT token: %v", token)
	return nil, &errors.OAuthError{Msg: errors.InternalServerError}
}

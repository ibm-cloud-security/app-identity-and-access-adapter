package ibmcloudappid

import (
	"crypto"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/golang/glog"
	"istio.io/istio/pkg/log"
)

// JWTTokenParser parses and validates JWT tokens
type JWTTokenParser interface {
	Parse(pubkeys map[string]crypto.PublicKey, token string) (*jwt.Token, error)
	Validate(pubkeys map[string]crypto.PublicKey, token string, tenantID string) error
}

type defaultJWTParser struct{}

// ParseToken parses the give token
// The underlying Parse function already verifies the ExpiresAt and NotBefore claims
func (parser *defaultJWTParser) Parse(pubkeys map[string]crypto.PublicKey, token string) (*jwt.Token, error) {
	log.Info(">> Parse")
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if kid == "" || !ok {
			log.Info(">> Parse: kid is missing")
			return nil, fmt.Errorf("kid is missing")
		}

		pk := pubkeys[kid]
		if pk == nil {
			log.Infof(">> Parse: kid not found: %s", token.Header["kid"])
			return nil, fmt.Errorf("Undefined kid: %s", token.Header["kid"])
		}
		return pk, nil
	})
}

// Validate a JWT against a public key and given claims
func (parser *defaultJWTParser) Validate(publicKeys map[string]crypto.PublicKey, token string, tenantID string) error {
	// Parse the token, and validate expiration, and clientID
	log.Info(">> Validate Token")
	tkn, err := parser.Parse(publicKeys, token)

	// Token is valid. The user is authenticated.
	if err != nil {
		return err
	}

	claims, ok := getClaims(tkn)
	if ok != true {
		log.Info(">> Validate token: Error Obtaining Claims from Access Token")
		return fmt.Errorf("Validate token: Error Obtaining Claims from Access Token")
	}

	if claimTenant, ok := claims["tenant"].(string); ok {
		if claimTenant != tenantID {
			log.Info(">> Validate token: Tenant in Claim %v does not match Tenant in bind Secret %v")
			return fmt.Errorf("Validate token: Tenant in Claim %v does not match Tenant in bind Secret %v", claimTenant, tenantID)
		}
	} else {
		log.Info("Error Obtaining Tenant from Claims")
		return fmt.Errorf("Validate token: Error Obtaining Tenant from Claims")
	}

	return nil

}

// Retrieve claims from JWT
func getClaims(token *jwt.Token) (jwt.MapClaims, bool) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	}
	glog.Errorf("getClaims: Invalid JWT Token: %v", token)
	return nil, false
}

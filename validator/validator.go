package validator

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/golang/glog"
	"istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/pkg/log"
)

// TokenValidator parses and validates JWT tokens
type TokenValidator interface {
	Parse(client client.Client, token string) (*jwt.Token, error)
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
func (*Validator) Parse(client client.Client, token string) (*jwt.Token, error) {
	log.Info(">> Parse")
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if kid == "" || !ok {
			log.Info(">> Parse: kid is missing")
			return nil, fmt.Errorf("kid is missing")
		}

		pubkeys := client.KeyUtil.PublicKeys()
		pk := pubkeys[kid]
		if pk == nil {
			log.Infof(">> Parse: kid not found: %s", token.Header["kid"])
			return nil, fmt.Errorf("Undefined kid: %s", token.Header["kid"])
		}
		return pk, nil
	})
}

// Validate a JWT against a public key and given claims
func (parser *Validator) Validate(client client.Client, token string) error {
	// Parse the token, and validate expiration, and clientID
	log.Info(">> Validate Token")
	tkn, err := parser.Parse(client, token)

	// Token is valid. The user is authenticated.
	if err != nil {
		return err
	}

	claims, ok := getClaims(tkn)
	if ok != true {
		log.Info(">> Validate token: Error Obtaining Claims from Access Token")
		return fmt.Errorf("Validate token: Error Obtaining Claims from Access Token")
	}

	// TODO: Validate audience, validate scopes, validate other
	if tenant, ok := claims["tenant"].(string); ok {
		if tenant != client.Name { // Validate Tenant ID
			log.Info(">> Validate token: Tenant in Claim %v does not match Tenant in bind Secret %v")
			return fmt.Errorf("Validate token: Tenant in Claim %v does not match Tenant in bind Secret %v", tenant, client.Name)
		}
	} else {
		log.Info("Error Obtaining Tenant from Claims")
		return fmt.Errorf("Validate token: Error Obtaining Tenant from Claims")
	}

	return nil

}

////////////////// utils //////////////////////////

// Retrieve claims from JWT
func getClaims(token *jwt.Token) (jwt.MapClaims, bool) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	}
	glog.Errorf("getClaims: Invalid JWT Token: %v", token)
	return nil, false
}

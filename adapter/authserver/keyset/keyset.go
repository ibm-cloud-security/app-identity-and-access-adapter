// Package keyset contains entities to control JSON Web Key Sets (JWKS)
package keyset

import (
	"crypto"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"golang.org/x/sync/singleflight"

	cstmErrs "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/errors"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/networking"
)

// KeySet retrieves public keys from OAuth server
type KeySet interface {
	PublicKeyURL() string
	PublicKey(kid string) crypto.PublicKey
}

// RemoteKeySet manages the retrieval and storage of OIDC public keys
type RemoteKeySet struct {
	publicKeyURL string
	httpClient   *networking.HTTPClient

	requestGroup singleflight.Group
	publicKeys   map[string]crypto.PublicKey
}

////////////////// constructor //////////////////////////

// New creates a new Public Key Util
func New(publicKeyURL string, httpClient *networking.HTTPClient) KeySet {
	pku := RemoteKeySet{
		publicKeyURL: publicKeyURL,
		httpClient:   httpClient,
	}

	if httpClient == nil {
		pku.httpClient = networking.New()
	}

	err := pku.updateKeysGrouped()
	if err != nil {
		zap.L().Debug("Error loading public keys for url. Will retry later.", zap.String("url", publicKeyURL))
		return &pku
	}
	zap.L().Info("Synced JWKs successfully.", zap.String("url", publicKeyURL))
	return &pku
}

////////////////// instance methods  //////////////////////////

// PublicKey returns the public key with the specified kid
func (s *RemoteKeySet) PublicKey(kid string) crypto.PublicKey {
	if key := s.publicKeys[kid]; key != nil {
		return key
	}
	_ = s.updateKeysGrouped()
	return s.publicKeys[kid]
}

// PublicKeyURL returns the public key url for the instance
func (s *RemoteKeySet) PublicKeyURL() string {
	return s.publicKeyURL
}

// updateKeyGroup issues /publicKeys request using shared request group
func (s *RemoteKeySet) updateKeysGrouped() error {
	_, err, _ := s.requestGroup.Do(s.publicKeyURL, s.updateKeys)

	if err != nil {
		zap.L().Debug("An error occurred requesting public keys", zap.Error(err))
		return err
	}

	return nil
}

// updateKeys retrieves public keys from the OIDC server for the instance
func (s *RemoteKeySet) updateKeys() (interface{}, error) {

	req, err := http.NewRequest("GET", s.publicKeyURL, nil)
	if err != nil {
		zap.L().Warn("Failed to create public key request", zap.String("url", s.publicKeyURL))
		return nil, err
	}

	ks := new(keySet)
	oa2Err := new(cstmErrs.OAuthError)
	if res, err := s.httpClient.Do(req, ks, oa2Err); err != nil {
		zap.L().Info("Failed to retrieve public keys", zap.String("url", s.publicKeyURL), zap.Error(err))
		return nil, err
	} else if res.StatusCode != http.StatusOK {
		zap.L().Info("Failed to retrieve public keys", zap.String("url", s.publicKeyURL), zap.Error(oa2Err))
		return nil, oa2Err
	}

	// Convert JSON keys to crypto keys
	keymap := make(map[string]crypto.PublicKey)
	for _, k := range ks.Keys {
		if k.Kid == "" {
			zap.L().Info("Invalid public key format - missing kid", zap.String("url", s.publicKeyURL), zap.Error(err))
			continue
		}

		pubKey, err := k.decodePublicKey()
		if err != nil {
			zap.L().Warn("Could not decode public key err", zap.Error(err))
			continue
		}
		keymap[k.Kid] = pubKey
	}

	zap.L().Info("Synced public keys", zap.String("url", s.publicKeyURL))

	s.publicKeys = keymap

	return http.StatusOK, nil
}

// OK validates a KeySet Response
func (k *keySet) OK() error {
	if k.Keys == nil {
		return fmt.Errorf("invalid public keys response : missing keys array")
	}
	return nil
}

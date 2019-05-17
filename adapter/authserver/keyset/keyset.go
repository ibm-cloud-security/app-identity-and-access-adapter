// Package keyset contains entities to control JSON Web Key Sets (JWKS)
package keyset

import (
	"crypto"
	"errors"
	"net/http"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"golang.org/x/sync/singleflight"
	"istio.io/pkg/log"
)

// KeySet retrieves public keys from OAuth server
type KeySet interface {
	PublicKeyURL() string
	PublicKey(kid string) crypto.PublicKey
}

// RemoteKeySet manages the retrieval and storage of OIDC public keys
type RemoteKeySet struct {
	publicKeyURL string
	httpClient   *networking.HttpClient

	requestGroup singleflight.Group
	publicKeys   map[string]crypto.PublicKey
}

////////////////// constructor //////////////////////////

// New creates a new Public Key Util
func New(publicKeyURL string, httpClient *networking.HttpClient) KeySet {
	pku := RemoteKeySet{
		publicKeyURL: publicKeyURL,
		httpClient:   httpClient,
	}

	if httpClient == nil {
		pku.httpClient = networking.New()
	}

	err := pku.updateKeysGrouped()
	if err != nil {
		log.Debugf("Error loading public keys for url: %s. Will retry later.", publicKeyURL)
		return &pku
	}
	log.Infof("Synced JWKs successfully: %s", publicKeyURL)
	return &pku
}

////////////////// instance methods  //////////////////////////

// PublicKey returns the public key with the specified kid
func (s *RemoteKeySet) PublicKey(kid string) crypto.PublicKey {
	if key := s.publicKeys[kid]; key != nil {
		return key
	}
	s.updateKeysGrouped()
	return s.publicKeys[kid]
}

// PublicKeyURL returns the public key url for the instance
func (s *RemoteKeySet) PublicKeyURL() string {
	return s.publicKeyURL
}

// updateKeyGroup issues /publicKeys request using shared request group
func (s *RemoteKeySet) updateKeysGrouped() error {
	_, err, _ := s.requestGroup.Do(s.publicKeyURL, func() (interface{}, error) {
		return s.updateKeys()
	})

	if err != nil {
		log.Debugf("An error occurred requesting public keys: %v", err)
		return err
	}

	return nil
}

// updateKeys retrieves public keys from the OIDC server for the instance
func (s *RemoteKeySet) updateKeys() (interface{}, error) {

	req, err := http.NewRequest("GET", s.publicKeyURL, nil)
	if err != nil {
		log.Errorf("KeySet - failed to create public key request : %s", s.publicKeyURL)
		return nil, err
	}

	req.Header.Set("xFilterType", "IstioAdapter")

	var ks keySet
	if err := s.httpClient.Do(req, http.StatusOK, &ks); err != nil {
		log.Errorf("KeySet - failed to retrieve public keys for url: %s", s.publicKeyURL)
		return nil, err
	}

	// Convert JSON keys to crypto keys
	keymap := make(map[string]crypto.PublicKey)
	for _, k := range ks.Keys {
		if k.Kid == "" {
			log.Infof("KeySet - public key missing kid %s", k)
			continue
		}

		pubKey, err := k.decodePublicKey()
		if err != nil {
			log.Errorf("KeySet - could not decode public key err %s : %s", err, k)
			continue
		}
		keymap[k.Kid] = pubKey
	}

	log.Infof("KeySet - updated public keys for %s", s.publicKeyURL)

	s.publicKeys = keymap

	return http.StatusOK, nil
}

// OK validates a KeySet Response
func (k *keySet) OK() error {
	if k.Keys == nil {
		return errors.New("invalid public keys response : missing keys array")
	}
	return nil
}

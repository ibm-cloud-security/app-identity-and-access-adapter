// Package keyset contains entities to control JSON Web Key Sets (JWKS)
package keyset

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

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
	httpClient   *http.Client

	requestGroup singleflight.Group
	publicKeys   map[string]crypto.PublicKey
}

////////////////// constructor //////////////////////////

// New creates a new Public Key Util
func New(publicKeyURL string, httpClient *http.Client) KeySet {
	pku := RemoteKeySet{
		publicKeyURL: publicKeyURL,
		httpClient:   httpClient,
	}

	pku.updateKeysGrouped()

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

	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Errorf("KeySet - failed to retrieve public keys for url: %s", s.publicKeyURL)
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		log.Errorf("KeySet - failed to retrieve public keys for url %s", s.publicKeyURL)
		return nil, fmt.Errorf("public key url returned non 200 status code: %d", res.StatusCode)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var jwks []key
	var ks keySet

	if err := json.Unmarshal(body, &ks); err == nil { // an RFC compliant JWK Set object, extract key array
		jwks = ks.Keys
	} else if err := json.Unmarshal(body, &jwks); err != nil { // attempt to decode as JWK array directly
		return nil, err
	}

	keymap := make(map[string]crypto.PublicKey)
	for _, k := range jwks {
		if k.Kid == "" {
			log.Infof("KeySet - public key missing kid %s", k)
			continue
		}

		pubkey, err := k.decodePublicKey()
		if err != nil {
			log.Errorf("KeySet - could not decode public key err %s : %s", err, k)
			continue
		}
		keymap[k.Kid] = pubkey
	}

	log.Infof("KeySet - updated public keys for %s", s.publicKeyURL)

	s.publicKeys = keymap

	return res.Status, nil
}

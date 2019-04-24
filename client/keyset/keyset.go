package keyset

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"istio.io/istio/pkg/log"
	"net/http"
	"sync"
	"time"
)

// KeySet retrieves public keys from OAuth server
type KeySet interface {
	RetrievePublicKeys() error
	PublicKeys() map[string]crypto.PublicKey
	PublicKey(kid string) crypto.PublicKey
}

// RemoteKeySet manages the retrieval and storage of OIDC public keys
type RemoteKeySet struct {
	publicKeyURL string
	httpClient   *http.Client

	// guard all other fields
	mu sync.Mutex

	publicKeys map[string]crypto.PublicKey
}

////////////////// constructor //////////////////////////

// New creates a new Public Key Util
func New(publicKeyURL string) KeySet {
	pku := RemoteKeySet{
		publicKeyURL: publicKeyURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	// Retrieve the public keys which are used to verify the tokens
	for i := 0; i < 5; i++ {
		if err := pku.RetrievePublicKeys(); err != nil {
			log.Infof("Failed to get Public Keys. Assuming failure is temporary, will retry later...")
			log.Error(err.Error())
			if i == 4 {
				log.Errorf("Unable to Obtain Public Keys after multiple attempts. Please restart the Ingress Pods.")
			}
		} else {
			log.Infof("Success. Public Keys Obtained...")
			break
		}
	}

	return &pku
}

////////////////// instance methods  //////////////////////////

// PublicKey returns the public key with the specified kid
func (s *RemoteKeySet) PublicKey(kid string) crypto.PublicKey {
	return s.publicKeys[kid]
}

// PublicKeys returns the public keys for the instance
func (s *RemoteKeySet) PublicKeys() map[string]crypto.PublicKey {
	return s.publicKeys
}

// RetrievePublicKeys retrieves public keys from the OIDC server for the instance
func (s *RemoteKeySet) RetrievePublicKeys() error {

	req, err := http.NewRequest("GET", s.publicKeyURL, nil)
	if err != nil {
		log.Errorf("RetrievePublicKeys - Failed to create public key request : %s", s.publicKeyURL)
		return err
	}

	req.Header.Set("xFilterType", "IstioAdapter")

	res, err := s.httpClient.Do(req)
	if err != nil {
		log.Errorf("RetrievePublicKeys - Failed to retrieve public keys for url: %s", s.publicKeyURL)
		return err
	}

	if res.StatusCode != http.StatusOK {
		log.Errorf("RetrievePublicKeys - Failed to retrieve public keys for url %s", s.publicKeyURL)
		return fmt.Errorf("public key url returned non 200 status code: %d", res.StatusCode)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var keys []key
	var ks keySet

	if err := json.Unmarshal(body, &ks); err == nil { // an RFC compliant JWK Set object, extract key array
		keys = ks.Keys
	} else if err := json.Unmarshal(body, &keys); err != nil { // attempt to decode as JWK array directly
		return err
	}

	mkeys := make(map[string]crypto.PublicKey)
	for _, k := range keys {
		if k.Kid == "" {
			log.Errorf("RetrievePublicKeys - public key missing kid %s", k)
			continue
		}

		pubkey, err := k.decodePublicKey()
		if err != nil {
			log.Errorf("RetrievePublicKeys - could not decode public key err %s : %s", err, k)
			continue
		}
		mkeys[k.Kid] = pubkey
	}

	s.publicKeys = mkeys

	return nil
}

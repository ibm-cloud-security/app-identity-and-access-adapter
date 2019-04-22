package keyutil

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"istio.io/istio/pkg/log"
)

// KeyUtil retrieves public keys from OAuth server
type KeyUtil interface {
	RetrievePublicKeys() error
	PublicKeys() map[string]crypto.PublicKey
}

// Util manages the retrieval and storage of OIDC public keys
type Util struct {
	publicKeys   map[string]crypto.PublicKey
	publicKeyURL string
}

////////////////// constructor //////////////////////////

// New creates a new Public Key Util
func New(publicKeyURL string) KeyUtil {
	pku := Util{
		publicKeyURL: publicKeyURL,
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

// PublicKeys returns the public keys for the instance
func (s *Util) PublicKeys() map[string]crypto.PublicKey {
	return s.publicKeys
}

// RetrievePublicKeys retrieves public keys from the OIDC server for the instance
func (s *Util) RetrievePublicKeys() error {

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", s.publicKeyURL, nil)
	if err != nil {
		log.Errorf("RetrievePublicKeys >> Failed to create public key request : %s", s.publicKeyURL)
		return err
	}

	req.Header.Set("xFilterType", "IstioAdapter")

	res, err := httpClient.Do(req)
	if err != nil {
		log.Errorf("RetrievePublicKeys >> Failed to retrieve public keys : %s", s.publicKeyURL)
		return err
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("getPubKeys: Failed to retrieve the public keys from %s with status: %d(%s)", s.publicKeyURL, res.StatusCode, http.StatusText(res.StatusCode))
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
	for i, k := range keys {
		if k.Kid == "" {
			return fmt.Errorf("getPubKeys: Failed to parse the public key %d: kid is missing", i)
		}

		pubkey, err := k.decodePublicKey()
		if err != nil {
			return fmt.Errorf("getPubKeys: Failed to parse the public key %d: %s", i, err)
		}
		mkeys[k.Kid] = pubkey
	}

	s.publicKeys = mkeys

	return nil
}

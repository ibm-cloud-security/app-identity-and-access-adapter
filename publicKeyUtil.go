package ibmcloudappid

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"istio.io/istio/pkg/log"
)

// PublicKeyUtil retries public keys from OAuth server
type PublicKeyUtil interface {
	RetrievePublicKeys() error
	GetPublicKeys() map[string]crypto.PublicKey
}

type defaultPublicKeyUtil struct {
	interval     time.Duration
	publicKeys   map[string]crypto.PublicKey
	publicKeyURL string
}

// NewPublicKeyUtil Create a new Public Key Util
func NewPublicKeyUtil(publicKeyURL string, interval time.Duration) *defaultPublicKeyUtil {
	pku := defaultPublicKeyUtil{
		publicKeyURL: publicKeyURL,
		interval:     interval,
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

func (s *defaultPublicKeyUtil) GetPublicKeys() map[string]crypto.PublicKey {
	return s.publicKeys
}

func (s *defaultPublicKeyUtil) RetrievePublicKeys() error {
	var publicKeyURL = "https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v3/71b34890-a94f-4ef2-a4b6-ce094aa68092/publickeys"

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get(publicKeyURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("getPubKeys: Failed to retrieve the public keys from %s with status: %d(%s)", publicKeyURL, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
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

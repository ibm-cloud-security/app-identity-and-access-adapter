package client

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"istio.io/istio/mixer/adapter/ibmcloudappid/client/keyset"
	"istio.io/istio/pkg/log"
	"net/http"
	"time"
)

// Type represents a client type (OIDC/OAuth2)
type Type int

const (
	// OAuth2 client
	OAuth2 Type = iota
	// OIDC client
	OIDC
)

// Config encasulates an authn/z client definition
type Config struct {
	Name         string
	ClientID     string
	Secret       string
	DiscoveryURL string
	Type         Type `json:"type"`
}

// ProviderConfig encasulates the discovery endpoint configuration
type ProviderConfig struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// Client encapsulates an authn/z client object
type Client struct {
	Config
	ProviderConfig
	KeySet     keyset.KeySet
	httpClient *http.Client
}

// New creates a new policy
func New(cfg Config) Client {
	client := Client{
		Config: cfg,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	err := client.load()
	if err != nil {
		log.Infof("Could not load client")
		return client
	}
	log.Infof("Loaded Client Successfully")
	client.KeySet = keyset.New(client.JWKSURL, client.httpClient)
	return client
}

func (c *Client) load() error {

	req, err := http.NewRequest("GET", c.DiscoveryURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("xFilterType", "IstioAdapter")

	res, err := c.httpClient.Do(req)
	if err != nil {
		log.Infof("Error %s", err)
		return err
	}

	if res.StatusCode != http.StatusOK {
		log.Infof("Error status code %d", res.StatusCode)
		return errors.New("unexpected error code")
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Infof("Error parsing response %s", err)
		return err
	}

	var config ProviderConfig

	if err := json.Unmarshal(body, &config); err == nil {
		c.ProviderConfig = config
	}

	return nil
}

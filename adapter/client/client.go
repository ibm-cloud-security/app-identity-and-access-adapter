package client

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"istio.io/pkg/log"
)

// ProviderConfig encapsulates the discovery endpoint configuration
type ProviderConfig struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// Client encapsulates an authn/z client object
type Client struct {
	v1.OidcClientSpec
	ProviderConfig
	AuthServer authserver.AuthorizationServer
	httpClient *http.Client
}

// New creates a new policy
func New(cfg v1.OidcClientSpec) Client {
	client := Client{
		OidcClientSpec: cfg,
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
	return client
}

func (c *Client) load() error {

	req, err := http.NewRequest("GET", c.DiscoveryUrl, nil)
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

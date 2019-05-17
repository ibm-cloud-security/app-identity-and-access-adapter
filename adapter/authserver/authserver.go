// Package authserver models an OAuth 2.0 Authorization Server
package authserver

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/groupcache/singleflight"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"istio.io/pkg/log"
)

// DiscoveryConfig encapsulates the discovery endpoint configuration
type DiscoveryConfig struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// AuthorizationServer represents an authorization server instance
type AuthorizationServer interface {
	JwksEndpoint() string
	TokenEndpoint() string
	AuthorizationEndpoint() string
	KeySet() keyset.KeySet
	SetKeySet(keyset.KeySet)
}

// RemoteServer represents a remote authentication server
// Configuration is loaded asynchronously from the discovery endpoint
type RemoteServer struct {
	DiscoveryConfig
	discoveryURL string
	jwks         keyset.KeySet
	httpclient   *http.Client
	requestGroup singleflight.Group
	initialized  bool
}

// New creates a RemoteServer returning a AuthorizationServer interface
func New(discoveryEndpoint string) AuthorizationServer {
	s := &RemoteServer{
		httpclient: &http.Client{
			Timeout: 5 * time.Second,
		},
		discoveryURL: discoveryEndpoint,
		jwks:         nil,
		initialized:  false,
	}
	err := s.initialize()
	if err != nil {
		log.Infof("Could not load authorization server config from discovery endpoint: %s. Will retry later.", discoveryEndpoint)
		return s
	}
	log.Infof("Loaded discovery configuration successfully: %s", discoveryEndpoint)
	return s
}

// KeySet returns the instance's keyset
func (s *RemoteServer) KeySet() keyset.KeySet {
	_ = s.initialize()
	if s.jwks == nil && s.JWKSURL != "" {
		s.jwks = keyset.New(s.JWKSURL, s.httpclient)
	}
	return s.jwks
}

// SetKeySet stores a JWKs in the OAuth server
func (s *RemoteServer) SetKeySet(jwks keyset.KeySet) {
	s.jwks = jwks
}

// JwksEndpoint returns the /publicKeys endpoint of the OAuth server
func (s *RemoteServer) JwksEndpoint() string {
	_ = s.initialize()
	return s.JWKSURL
}

// TokenEndpoint returns the /token endpoint of the OAuth server
func (s *RemoteServer) TokenEndpoint() string {
	_ = s.initialize()
	return s.TokenURL
}

// AuthorizationEndpoint returns the /authorization endpoint of the OAuth server
func (s *RemoteServer) AuthorizationEndpoint() string {
	_ = s.initialize()
	return s.AuthURL
}

// initialize attempts to load the Client configuration from the discovery endpoint
func (s *RemoteServer) initialize() error {
	if s.initialized {
		return nil
	}
	_, err := s.requestGroup.Do(s.discoveryURL, func() (interface{}, error) {
		return s.loadDiscoveryEndpoint()
	})

	if err != nil {
		log.Debugf("An error occurred loading: %v", err)
		return err
	}

	return nil
}

// loadDiscoveryEndpoint loads the configuration from the discovery endpoint
func (s *RemoteServer) loadDiscoveryEndpoint() (interface{}, error) {
	req, err := http.NewRequest("GET", s.discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("xFilterType", "IstioAdapter")

	res, err := s.httpclient.Do(req)
	if err != nil {
		log.Infof("Error %s", err)
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		log.Infof("Error status code %d", res.StatusCode)
		return nil, errors.New("unexpected error code")
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Infof("Error parsing response %s", err)
		return nil, err
	}

	var config DiscoveryConfig

	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}

	s.initialized = true
	s.DiscoveryConfig = config

	return res.Status, nil
}

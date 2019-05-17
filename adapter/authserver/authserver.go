// Package authserver models an OAuth 2.0 Authorization Server
package authserver

import (
	"errors"
	"github.com/golang/groupcache/singleflight"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"istio.io/pkg/log"
	"net/http"
)

// DiscoveryConfig encapsulates the discovery endpoint configuration
type DiscoveryConfig struct {
	DiscoveryUrl string
	Issuer       string `json:"issuer"`
	AuthURL      string `json:"authorization_endpoint"`
	TokenURL     string `json:"token_endpoint"`
	JwksURL      string `json:"jwks_uri"`
	UserInfoURL  string `json:"userinfo_endpoint"`
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
	httpclient   *networking.HttpClient
	requestGroup singleflight.Group
	initialized  bool
}

// New creates a RemoteServer returning a AuthorizationServer interface
func New(discoveryEndpoint string) AuthorizationServer {
	s := &RemoteServer{
		httpclient:   networking.New(),
		discoveryURL: discoveryEndpoint,
		jwks:         nil,
		initialized:  false,
	}
	err := s.initialize()
	if err != nil {
		log.Infof("Initialization from discovery endpoint failed: %s. Will retry later.", discoveryEndpoint)
		return s
	}
	log.Infof("Initialized discovery configuration successfully: %s", discoveryEndpoint)
	return s
}

// KeySet returns the instance's keyset
func (s *RemoteServer) KeySet() keyset.KeySet {
	_ = s.initialize()
	if s.jwks == nil && s.JwksURL != "" {
		s.jwks = keyset.New(s.JwksURL, s.httpclient)
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
	return s.JwksURL
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

	// Retrieve configuration from .well-known endpoint.
	// RequestGroup will prevent multiple calls to the discovery url from
	// taking place at once. All threads coming into this call will wait for
	// a single response, which can then be processed
	_, err := s.requestGroup.Do(s.discoveryURL, func() (interface{}, error) {
		if s.initialized {
			return http.StatusOK, nil
		}
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

	config := DiscoveryConfig{
		DiscoveryUrl: s.discoveryURL,
	}

	if err := s.httpclient.Do(req, http.StatusOK, &config); err != nil {
		return nil, err
	}

	s.initialized = true
	s.DiscoveryConfig = config

	return http.StatusOK, nil
}

// OK validates the result from a discovery configuration
func (c *DiscoveryConfig) OK() error {
	if c.Issuer == "" {
		return errors.New("invalid discovery config: missing `issuer`")
	}
	if c.JwksURL == "" {
		return errors.New("invalid discovery config: missing `jwks_uri`")
	}
	if c.AuthURL == "" {
		return errors.New("invalid discovery config: missing `authorization_endpoint`")
	}
	if c.TokenURL == "" {
		return errors.New("invalid discovery config: missing `token_endpoint`")
	}
	if c.UserInfoURL == "" {
		return errors.New("invalid discovery config: missing `userinfo_endpoint`")
	}
	return nil
}

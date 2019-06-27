// Package authserver models an OAuth 2.0 Authorization Server
package authserver

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang/groupcache/singleflight"
	"go.uber.org/zap"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	cstmErrs "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/errors"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/networking"
)

const (
	clientPostSecret = "client_secret_post"
	//clientPostBasic  = "client_basic_post"
)

// DiscoveryConfig encapsulates the discovery endpoint configuration
type DiscoveryConfig struct {
	DiscoveryURL string
	Issuer       string `json:"issuer"`
	AuthURL      string `json:"authorization_endpoint"`
	TokenURL     string `json:"token_endpoint"`
	JwksURL      string `json:"jwks_uri"`
	UserInfoURL  string `json:"userinfo_endpoint"`
}

// TokenResponse models an OAuth 2.0 /Value endpoint response
type TokenResponse struct {
	// The OAuth 2.0 Access Value
	AccessToken string `json:"access_token"`
	// The OIDC ID Value
	IdentityToken string `json:"id_token"`
	// The OAuth 2.0 Refresh Value
	RefreshToken string `json:"refresh_token"`
	// The token expiration time
	ExpiresIn int `json:"expires_in"`
}

// AuthorizationServerService represents an authorization server instance
type AuthorizationServerService interface {
	JwksEndpoint() string
	TokenEndpoint() string
	AuthorizationEndpoint() string
	UserInfoEndpoint() string
	KeySet() keyset.KeySet
	SetKeySet(keyset.KeySet)
	GetTokens(authnMethod string, clientID string, clientSecret string, authorizationCode string, redirectURI string, refreshToken string) (*TokenResponse, error)
}

// RemoteService represents a remote authentication server
// Configuration is loaded asynchronously from the discovery endpoint
type RemoteService struct {
	DiscoveryConfig
	discoveryURL string
	jwks         keyset.KeySet
	httpclient   *networking.HTTPClient
	requestGroup singleflight.Group
	initialized  bool
}

// New creates a RemoteService returning a AuthorizationServerService interface
func New(discoveryEndpoint string) AuthorizationServerService {
	s := &RemoteService{
		httpclient:   networking.New(),
		discoveryURL: discoveryEndpoint,
		jwks:         nil,
		initialized:  false,
	}
	err := s.initialize()
	if err != nil {
		zap.L().Debug("Initialization from discovery endpoint failed. Will retry later.", zap.String("url", discoveryEndpoint))
		return s
	}
	zap.L().Debug("Initialized discovery configuration successfully", zap.String("url", discoveryEndpoint))
	return s
}

// KeySet returns the instance's keyset
func (s *RemoteService) KeySet() keyset.KeySet {
	_ = s.initialize()
	if s.jwks == nil && s.JwksURL != "" {
		s.jwks = keyset.New(s.JwksURL, s.httpclient)
	}
	return s.jwks
}

// SetKeySet stores a JWKs in the OAuth server
func (s *RemoteService) SetKeySet(jwks keyset.KeySet) {
	s.jwks = jwks
}

// JwksEndpoint returns the /publicKeys endpoint of the OAuth server
func (s *RemoteService) JwksEndpoint() string {
	_ = s.initialize()
	return s.JwksURL
}

// TokenEndpoint returns the /token endpoint of the OAuth server
func (s *RemoteService) TokenEndpoint() string {
	_ = s.initialize()
	return s.TokenURL
}

// AuthorizationEndpoint returns the /authorization endpoint of the OAuth server
func (s *RemoteService) AuthorizationEndpoint() string {
	_ = s.initialize()
	return s.AuthURL
}

// UserInfoEndpoint returns the /userinfo endpoint of the OAuth server
func (s *RemoteService) UserInfoEndpoint() string {
	_ = s.initialize()
	return s.UserInfoURL
}

// GetTokens performs a request to the token endpoint
func (s *RemoteService) GetTokens(authnMethod string, clientID string, clientSecret string, authorizationCode string, redirectURI string, refreshToken string) (*TokenResponse, error) {
	_ = s.initialize()
	form := url.Values{
		"client_id": {clientID},
	}
	if refreshToken != "" {
		form.Add("grant_type", "refresh_token")
		form.Add("refresh_token", refreshToken)
	} else {
		form.Add("grant_type", "authorization_code")
		form.Add("code", authorizationCode)
		form.Add("redirect_uri", redirectURI)
	}

	if authnMethod == clientPostSecret {
		form.Add("client_id", clientID)
		form.Add("client_secret", clientSecret)
	}

	// Create request
	req, err := http.NewRequest("POST", s.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		zap.L().Warn("Could not serialize HTTP request", zap.Error(err))
		return nil, err
	}

	// All other methods will default to client_post_basic
	if authnMethod != clientPostSecret {
		req.SetBasicAuth(clientID, clientSecret)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResponse := new(TokenResponse)
	oa2Err := new(cstmErrs.OAuthError)
	if res, err := s.httpclient.Do(req, tokenResponse, oa2Err); err != nil {
		zap.L().Info("Failed to retrieve tokens", zap.Error(err))
		return nil, err
	} else if res.StatusCode != http.StatusOK {
		zap.L().Info("Failed to retrieve tokens", zap.Error(oa2Err))
		return nil, oa2Err
	}

	return tokenResponse, nil
}

// initialize attempts to load the Client configuration from the discovery endpoint
func (s *RemoteService) initialize() error {
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
		zap.L().Debug("Could not sync discovery endpoint", zap.String("url", s.discoveryURL), zap.Error(err))
		return err
	}

	return nil
}

// loadDiscoveryEndpoint loads the configuration from the discovery endpoint
func (s *RemoteService) loadDiscoveryEndpoint() (interface{}, error) {
	req, err := http.NewRequest("GET", s.discoveryURL, nil)
	if err != nil {
		zap.L().Debug("Could not sync discovery endpoint", zap.String("url", s.discoveryURL), zap.Error(err))
		return nil, err
	}

	config := new(DiscoveryConfig)
	config.DiscoveryURL = s.discoveryURL
	oa2Err := new(cstmErrs.OAuthError)
	if res, err := s.httpclient.Do(req, config, oa2Err); err != nil {
		zap.L().Debug("Could not sync discovery endpoint", zap.String("url", s.discoveryURL), zap.Error(err))
		return nil, err
	} else if res.StatusCode != http.StatusOK {
		zap.L().Debug("Could not sync discovery endpoint", zap.String("url", s.discoveryURL), zap.Error(oa2Err))
		return nil, oa2Err
	}

	s.initialized = true
	s.DiscoveryConfig = *config

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

// OK validates a TokenResponse
func (r *TokenResponse) OK() error {
	if r.AccessToken == "" {
		return errors.New("invalid token endpoint response: access_token does not exist")
	}
	return nil
}

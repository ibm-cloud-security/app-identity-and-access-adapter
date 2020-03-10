package client

import (
	"errors"

	"go.uber.org/zap"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver"
	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
)

// Client encapsulates an authn/z client object
type Client interface {
	Name() string
	ID() string
	Callback() string
	Secret() string
	AuthorizationServer() authserver.AuthorizationServerService
	ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error)
	RefreshToken(refreshToken string) (*authserver.TokenResponse, error)
}

type remoteClient struct {
	v1.OidcConfigSpec
	authServer authserver.AuthorizationServerService
}

func (c *remoteClient) Name() string {
	return c.ClientName
}

func (c *remoteClient) ID() string {
	return c.ClientID
}

func (c *remoteClient) Callback() string {
	return c.ClientCallback
}

func (c *remoteClient) Secret() string {
	return c.ClientSecret
}

func (c *remoteClient) AuthorizationServer() authserver.AuthorizationServerService {
	return c.authServer
}

func (c *remoteClient) ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error) {
	if c.authServer == nil {
		zap.L().Error("invalid configuration :: missing authorization server", zap.String("client_name", c.ClientName))
		return nil, errors.New("invalid client configuration :: missing authorization server")
	}
	return c.authServer.GetTokens(c.AuthMethod, c.ClientID, c.ClientSecret, code, redirectURI, "")
}

func (c *remoteClient) RefreshToken(refreshToken string) (*authserver.TokenResponse, error) {
	if c.authServer == nil {
		zap.L().Error("invalid configuration :: missing authorization server", zap.String("client_name", c.ClientName))
		return nil, errors.New("invalid client configuration :: missing authorization server")
	}
	return c.authServer.GetTokens(c.AuthMethod, c.ClientID, c.ClientSecret, "", "", refreshToken)
}

// New creates a new client
func New(cfg v1.OidcConfigSpec, s authserver.AuthorizationServerService) Client {
	return &remoteClient{
		OidcConfigSpec: cfg,
		authServer:     s,
	}
}

package client

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"go.uber.org/zap"
)

// Client encapsulates an authn/z client object
type Client interface {
	Name() string
	ID() string
	Secret() string
	AuthorizationServer() authserver.AuthorizationServer
	ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error)
}

type remoteClient struct {
	v1.OidcClientSpec
	authServer authserver.AuthorizationServer
}

func (c *remoteClient) Name() string {
	return c.ClientName
}

func (c *remoteClient) ID() string {
	return c.ClientID
}

func (c *remoteClient) Secret() string {
	return c.ClientSecret
}

func (c *remoteClient) AuthorizationServer() authserver.AuthorizationServer {
	return c.authServer
}

func (c *remoteClient) ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error) {
	if c.authServer == nil {
		zap.L().Error("invalid configuration :: missing authorization server", zap.String("client_name", c.ClientName))
		return nil, errors.New("invalid client configuration :: missing authorization server")
	}
	return c.authServer.GetTokens(c.AuthMethod, c.ClientID, c.ClientSecret, code, redirectURI)
}

// New creates a new client
func New(cfg v1.OidcClientSpec, s authserver.AuthorizationServer) Client {
	return &remoteClient{
		OidcClientSpec: cfg,
		authServer:     s,
	}
}

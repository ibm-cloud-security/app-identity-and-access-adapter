package client

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
)

// Client encapsulates an authn/z client object
type Client interface {
	Name() string
	ID() string
	Secret() string
	AuthorizationServer() authserver.AuthorizationServer
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

// New creates a new client
func New(cfg v1.OidcClientSpec, s authserver.AuthorizationServer) Client {
	return &remoteClient{
		OidcClientSpec: cfg,
		authServer:     s,
	}
}

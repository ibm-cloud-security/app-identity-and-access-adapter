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

type RemoteClient struct {
	v1.OidcClientSpec
	authServer authserver.AuthorizationServer
}

func (c *RemoteClient) Name() string {
	return c.ClientName
}

func (c *RemoteClient) ID() string {
	return c.ClientId
}

func (c *RemoteClient) Secret() string {
	return c.ClientSecret
}

func (c *RemoteClient) AuthorizationServer() authserver.AuthorizationServer {
	return c.authServer
}

// New creates a new client
func New(cfg v1.OidcClientSpec, s authserver.AuthorizationServer) Client {
	return &RemoteClient{
		OidcClientSpec: cfg,
		authServer:     s,
	}
}

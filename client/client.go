package client

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/client/keyutil"
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

// Client encapsulates an authn/z client object
type Client struct {
	Config
	KeyUtil keyutil.KeyUtil
}

// New creates a new policy
func New(cfg Config) Client {
	return Client{
		Config:  cfg,
		KeyUtil: keyutil.New("https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v3/71b34890-a94f-4ef2-a4b6-ce094aa68092/publicKeys"), // TODO: // this needs to be the public keys URL
	}
}

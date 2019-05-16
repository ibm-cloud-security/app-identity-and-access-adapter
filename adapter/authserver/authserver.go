// Package authserver models an OAuth 2.0 Authorization Server
package authserver

import (
	"net/http"
	"time"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
)

// AuthorizationServer represents an authorization server instance
type AuthorizationServer interface {
	KeySet() keyset.KeySet
}

// RemoteServer represents a remote authentication server
// Keys are retrieved from a remote data source
type RemoteServer struct {
	keyset     keyset.KeySet
	httpclient *http.Client
}

// KeySet returns the instance's keyset
func (a *RemoteServer) KeySet() keyset.KeySet {
	return a.keyset
}

// New creates a RemoteServer returning a AuthorizationServer interface
func New(jwksURL string) AuthorizationServer {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	return &RemoteServer{
		httpclient: client,
		keyset:     keyset.New(jwksURL, client),
	}
}

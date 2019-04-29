package authserver

import (
	"net/http"
	"time"

	"ibmcloudappid/authserver/keyset"
)

type AuthorizationServer interface {
	KeySet() keyset.KeySet
}

type RemoteServer struct {
	keyset     keyset.KeySet
	httpclient *http.Client
}

func (a *RemoteServer) KeySet() keyset.KeySet {
	return a.keyset
}

func New(jwksURL string) AuthorizationServer {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	return &RemoteServer{
		httpclient: client,
		keyset:     keyset.New(jwksURL, client),
	}
}
package authserver

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/authserver/keyset"
)

type AuthorizationServer interface {
	KeySet() keyset.KeySet
}

type RemoteServer struct {
	keyset keyset.KeySet
}

func (a *RemoteServer) KeySet() keyset.KeySet {
	return a.keyset
}

func New(keyset keyset.KeySet) AuthorizationServer {
	return &RemoteServer{
		keyset: keyset,
	}
}

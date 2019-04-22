package strategy

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/authorization"
)

// Strategy defines the entry point to an authentiation handler
type Strategy interface {
	HandleAuthorizationRequest(*authorization.HandleAuthorizationRequest, *client.Client) (*adapter.CheckResult, error)
}

package strategy

import (
	"ibmcloudappid/adapter/policy/manager"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/authorization"
)

// Strategy defines the entry point to an authentiation handler
type Strategy interface {
	HandleAuthorizationRequest(*authorization.HandleAuthorizationRequest, []manager.PolicyAction) (*adapter.CheckResult, error)
}

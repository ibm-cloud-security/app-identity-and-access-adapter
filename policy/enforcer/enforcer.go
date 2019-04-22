// Package enforcer is responsible for enforcing authn/z policy decision
package enforcer

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy"
)

type PolicyEnforcer interface {
	IsRequired(string) bool
	GetPolicies(string) []policy.Policy
}

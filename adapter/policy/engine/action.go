// Package engine is responsible for making policy decisions
package engine

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

// Action encapsulates information needed to begin executing a policy
type Action struct {
	v1.PathPolicy
	KeySet keyset.KeySet
	Client client.Client
	Rules  []policy.Rule
	Type   policy.Type
}

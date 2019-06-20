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
	// KeySet is used on JWT flows
	KeySet keyset.KeySet
	// Client is used on OIDC flows
	Client client.Client
	// Type the policy
	Type policy.Type
}

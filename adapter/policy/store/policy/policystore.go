package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

// PolicyStore stores policy information
type PolicyStore interface {
	GetKeySet(jwksURL string) keyset.KeySet
	AddKeySet(jwksURL string, jwks keyset.KeySet)
	GetClient(clientName string) client.Client
	AddClient(clientName string, client client.Client)
	GetPolicies(endpoint policy.Endpoint) []v1.PathPolicy
	SetPolicies(endpoint policy.Endpoint, actions []v1.PathPolicy)
	// DeletePolicies(ep policy.Endpoint, obj interface{})
	GetPolicyMapping(policy string) *policy.PolicyMapping
	AddPolicyMapping(policy string, mapping *policy.PolicyMapping)
	DeletePolicyMapping(policy string)
}

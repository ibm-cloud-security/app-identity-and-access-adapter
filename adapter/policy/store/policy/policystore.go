package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

// PolicyStore stores policy information
type PolicyStore interface {
	GetKeySet(jwksURL string) keyset.KeySet
	AddKeySet(jwksURL string, jwks keyset.KeySet)
	GetClient(clientName string) client.Client
	AddClient(clientName string, client client.Client)
	GetPolicies(endpoint string) policy.Actions
	SetPolicies(endpoint string, actions policy.Actions)
	// DeletePolicies(ep policy.Endpoint, obj interface{})
	AddPolicyMapping(policy string, mapping *policy.PolicyMapping)
	DeletePolicyMapping(policy string)
}

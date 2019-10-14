package policy

import (
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/client"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
)

// PolicyStore stores policy information
type PolicyStore interface {
	GetKeySet(clientName string) keyset.KeySet
	AddKeySet(clientName string, jwks keyset.KeySet)
	DeleteKeySet(clientName string)
	GetClient(clientName string) client.Client
	AddClient(clientName string, client client.Client)
	DeleteClient(clientName string)
	GetPolicies(endpoint policy.Endpoint) policy.RoutePolicy
	GetPrefixPolicies(endpoint policy.Endpoint) policy.RoutePolicy
	SetPolicies(endpoint policy.Endpoint, actions policy.RoutePolicy)
	DeletePolicies(ep policy.Endpoint)
	GetPolicyMapping(policy string) []policy.PolicyMapping
	AddPolicyMapping(policy string, mapping []policy.PolicyMapping)
	DeletePolicyMapping(policy string)
}

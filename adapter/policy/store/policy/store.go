package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

// Store holds policy information
type Store interface {
	GetKeySet(clientName string) keyset.KeySet
	AddKeySet(clientName string, jwks keyset.KeySet)
	DeleteKeySet(clientName string)
	GetClient(clientName string) client.Client
	AddClient(clientName string, client client.Client)
	DeleteClient(clientName string)
	GetPolicies(endpoint policy.Endpoint) policy.RoutePolicy
	SetPolicies(endpoint policy.Endpoint, actions policy.RoutePolicy)
	// DeletePolicies(ep policy.Endpoint, obj interface{})
	GetPolicyMapping(policy string) []policy.Mapping
	AddPolicyMapping(policy string, mapping []policy.Mapping)
	DeletePolicyMapping(policy string)
}

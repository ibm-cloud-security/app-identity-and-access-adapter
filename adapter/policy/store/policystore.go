package store

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
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
	GetAuthServer(serverName string) authserver.AuthorizationServer
	AddAuthServer(serverName string, server authserver.AuthorizationServer)
	GetApiPolicies(ep policy.Endpoint) *policy.Action
	SetApiPolicy(ep policy.Endpoint, action policy.Action)
	//SetApiPolicies(ep policy.Endpoint, policy []engine.Action)
	DeleteApiPolicy(ep policy.Endpoint, obj interface{})
	GetWebPolicies(ep policy.Endpoint) *policy.Action
	SetWebPolicy(ep policy.Endpoint, action policy.Action)
	//SetWebPolicies(ep policy.Endpoint, policy []v1.OidcPolicySpec)
	DeleteWebPolicy(ep policy.Endpoint, obj interface{})
	GetPolicyMapping(policy string) *policy.PolicyMapping
	DeletePolicyMapping(policy string)
	AddPolicyMapping(policy string, mapping *policy.PolicyMapping)
}

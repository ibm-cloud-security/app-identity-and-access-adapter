package store

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

// PolicyStore stores policy information
type PolicyStore interface {
	GetClient(clientName string) *client.Client
	AddClient(clientName string, client *client.Client)
	GetAuthServer(serverName string) authserver.AuthorizationServer
	AddAuthServer(serverName string, server authserver.AuthorizationServer)
	GetApiPolicies(ep policy.Endpoint) []v1.JwtPolicySpec
	SetApiPolicy(ep policy.Endpoint, policy v1.JwtPolicySpec)
	SetApiPolicies(ep policy.Endpoint, policy []v1.JwtPolicySpec)
	DeleteApiPolicy(ep policy.Endpoint, obj interface{})
	GetWebPolicies(ep policy.Endpoint) []v1.OidcPolicySpec
	SetWebPolicy(ep policy.Endpoint, policy v1.OidcPolicySpec)
	SetWebPolicies(ep policy.Endpoint, policy []v1.OidcPolicySpec)
	DeleteWebPolicy(ep policy.Endpoint, obj interface{})
	GetPolicyMapping(policy string) *policy.PolicyMapping
	DeletePolicyMapping(policy string)
	AddPolicyMapping(policy string, mapping *policy.PolicyMapping)
}

package store

import (
	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/client"
	v1 "ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
)

// PolicyStore stores policy information
type PolicyStore interface {
	GetClient(clientName string) *client.Client
	AddClient(clientName string, client *client.Client)
	GetAuthServer(serverName string) authserver.AuthorizationServer
	AddAuthServer(serverName string, server authserver.AuthorizationServer)
	GetApiPolicies(ep policy.Endpoint) []v1.JwtPolicySpec
	SetApiPolicy(ep policy.Endpoint, policy v1.JwtPolicySpec)
	DeleteApiPolicy(ep policy.Endpoint, obj interface{})
	SetApiPolicies(ep policy.Endpoint, policy []v1.JwtPolicySpec)
	//GetWebPolicies(ep handler.Endpoint) []v1.OidcPolicySpec
	//SetWebPolicy(ep handler.Endpoint,policy v1.OidcPolicySpec)
	//SetWebPolicies(ep handler.Endpoint,policy []v1.OidcPolicySpec)
	GetPolicyMapping(policy string) *policy.PolicyMapping
	DeletePolicyMapping(policy string)
	AddPolicyMapping(policy string, mapping *policy.PolicyMapping)
}

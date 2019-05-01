package store

import (
	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/client"
	v1 "ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy/handler"
)

type PolicyStore interface {
	GetClient(clientName string) *client.Client
	AddClient(clientName string, client *client.Client)
	GetAuthServer(serverName string) authserver.AuthorizationServer
	AddAuthServer(serverName string, server authserver.AuthorizationServer)
	GetApiPolicies(ep handler.Endpoint) []v1.JwtPolicySpec
	SetApiPolicy(ep handler.Endpoint,policy v1.JwtPolicySpec)
	DeleteApiPolicy(ep handler.Endpoint, obj interface{})
	SetApiPolicies(ep handler.Endpoint,policy []v1.JwtPolicySpec)
	//GetWebPolicies(ep handler.Endpoint) []v1.OidcPolicySpec
	//SetWebPolicy(ep handler.Endpoint,policy v1.OidcPolicySpec)
	//SetWebPolicies(ep handler.Endpoint,policy []v1.OidcPolicySpec)
	GetPolicyMapping(policy string) *handler.PolicyMapping
	DeletePolicyMapping(policy string)
	AddPolicyMapping(policy string, mapping *handler.PolicyMapping)
}

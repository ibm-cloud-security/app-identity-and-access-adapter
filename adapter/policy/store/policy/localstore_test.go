package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
)

const (
	clientname   = "clientname"
	jwksurl      = "http://mockserver"
	endpoint     = "service/path"
	samplePolicy = "policy"
)

func getService() policy.Service {
	return policy.Service{
		Name:      "sample",
		Namespace: "ns",
	}
}

func getActions() policy.Actions {
	actions := policy.NewActions()
	actions[policy.GET] = policy.RoutePolicy {
		Actions: []v1.PathPolicy{
			{PolicyType: "jwt", Config:"samplejwt"},
		},
	}
	actions[policy.ALL] = policy.RoutePolicy {
		Actions: []v1.PathPolicy{
			{PolicyType:"oidc", Config:"sampleoidc", RedirectUri:"https://sampleapp.com"},
		},
	}
	return actions
}

func getEndpoint(service policy.Service, path string, method policy.Method) policy.Endpoint {
	return policy.Endpoint{
		Service: service,
		Path:    path,
		Method:  method,
	}
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New())
}

func keySetTest(t *testing.T, store PolicyStore) {
	assert.Nil(t, store.GetKeySet(jwksurl))
	store.AddKeySet(jwksurl, &fake.KeySet{})
	assert.NotNil(t, store.GetKeySet(jwksurl))
}
func TestLocalStore_KeySet(t *testing.T) {
	keySetTest(t, &LocalStore{})
	keySetTest(t, New())
}

func clientTest(t *testing.T, store PolicyStore) {
	assert.Nil(t, store.GetClient(clientname))
	store.AddClient(clientname, &fake.Client{})
	assert.NotNil(t, store.GetClient(clientname))
}
func TestLocalStore_Client(t *testing.T) {
	clientTest(t, &LocalStore{})
	clientTest(t, New())
}

func policiesTest(t *testing.T, store PolicyStore) {
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.GET)), policy.NewRoutePolicy())
	store.SetPolicies(getEndpoint(getService(), endpoint, policy.ALL),
		policy.RoutePolicy{ Actions:[]v1.PathPolicy{ {PolicyType:"oidc", Config:"sampleoidc", RedirectUri:"https://sampleapp.com"}}})
	store.SetPolicies(getEndpoint(getService(), endpoint, policy.GET),
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "jwt", Config:"samplejwt"}}})
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.GET)), getActions()[policy.GET])
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.PUT)), getActions()[policy.ALL])
}

func TestLocalStore_Policies(t *testing.T) {
	policiesTest(t, &LocalStore{})
	policiesTest(t, New())
}

func policyMappingTest(t *testing.T, store PolicyStore) {
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
	store.AddPolicyMapping(samplePolicy, []policy.PolicyMapping{})
	assert.NotNil(t, store.GetPolicyMapping(samplePolicy))
	store.DeletePolicyMapping(samplePolicy)
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
}
func TestLocalStore_PolicyMapping(t *testing.T) {
	policyMappingTest(t, &LocalStore{})
	policyMappingTest(t, New())
}

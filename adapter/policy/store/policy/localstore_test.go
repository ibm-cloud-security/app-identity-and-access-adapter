package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/fake"
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
	actions[policy.GET] = policy.RoutePolicy{
		Actions: []v1.PathPolicy{
			{PolicyType: "jwt", Config: "samplejwt"},
		},
	}
	actions[policy.ALL] = policy.RoutePolicy{
		Actions: []v1.PathPolicy{
			{PolicyType: "oidc", Config: "sampleoidc", RedirectUri: "https://sampleapp.com"},
		},
	}
	return actions
}

func getPrefixActions() policy.Actions {
	actions := policy.NewActions()
	actions[policy.GET] = policy.RoutePolicy{
		Actions: []v1.PathPolicy{
			{PolicyType: "jwt", Config: "prefix"},
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
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "oidc", Config: "sampleoidc", RedirectUri: "https://sampleapp.com"}}})
	store.SetPolicies(getEndpoint(getService(), endpoint, policy.GET),
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "jwt", Config: "samplejwt"}}})
	store.SetPolicies(getEndpoint(getService(), "/*", policy.GET),
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "jwt", Config: "prefix"}}})
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.GET)), getActions()[policy.GET])
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.ALL)), getActions()[policy.ALL])
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.PUT)), policy.NewRoutePolicy())
	assert.Equal(t, store.GetPrefixPolicies(getEndpoint(getService(), endpoint, policy.GET)), getPrefixActions()[policy.GET])
	assert.Equal(t, store.GetPrefixPolicies(getEndpoint(getService(), endpoint, policy.ALL)), policy.NewRoutePolicy())
}

func TestLocalStore_Policies(t *testing.T) {
	policiesTest(t, &LocalStore{})
	policiesTest(t, New())
}

func deletePoliciesTest(t *testing.T, store PolicyStore) {
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.GET)), policy.NewRoutePolicy())
	store.SetPolicies(getEndpoint(getService(), endpoint, policy.ALL),
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "oidc", Config: "sampleoidc", RedirectUri: "https://sampleapp.com"}}})
	store.SetPolicies(getEndpoint(getService(), endpoint, policy.GET),
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "jwt", Config: "samplejwt"}}})
	store.SetPolicies(getEndpoint(getService(), "/*", policy.GET),
		policy.RoutePolicy{Actions: []v1.PathPolicy{{PolicyType: "jwt", Config: "prefix"}}})
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.GET)), getActions()[policy.GET])
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.ALL)), getActions()[policy.ALL])
	assert.Equal(t, store.GetPrefixPolicies(getEndpoint(getService(), endpoint, policy.GET)), getPrefixActions()[policy.GET])
	store.DeletePolicies(getEndpoint(getService(), endpoint, policy.GET))
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.GET)), policy.NewRoutePolicy())
	store.DeletePolicies(getEndpoint(getService(), endpoint, policy.ALL))
	assert.Equal(t, store.GetPolicies(getEndpoint(getService(), endpoint, policy.ALL)), policy.NewRoutePolicy())
	store.DeletePolicies(getEndpoint(getService(), "/*", policy.GET))
	assert.Equal(t, store.GetPrefixPolicies(getEndpoint(getService(), "/*", policy.GET)), policy.NewRoutePolicy())
}
func TestLocalStore_DeletePolicies(t *testing.T) {
	deletePoliciesTest(t, &LocalStore{})
	deletePoliciesTest(t, New())
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

func serviceHostMapping(t *testing.T, store PolicyStore) {
	host := []string{"host"}
	assert.Nil(t, store.GetServiceHostMapping(getService()))
	store.SetServiceHostMapping(getService(), host)
	assert.Equal(t, store.GetServiceHostMapping(getService()), host)
	store.DeleteServiceHostMapping(getService())
	assert.Nil(t, store.GetServiceHostMapping(getService()))
}

func TestLocalStore_ServiceHostMapping(t *testing.T) {
	serviceHostMapping(t, &LocalStore{})
	serviceHostMapping(t, New())
}

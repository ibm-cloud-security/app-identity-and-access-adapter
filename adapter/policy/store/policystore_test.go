package store

import (
	"crypto"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	clientname   = "clientname"
	servername   = "servername"
	jwksurl      = "http://mockserver"
	service      = "service"
	namespace    = "ns"
	path         = "path"
	samplePolicy = "policy"
)

func GetEndpoint(ns string, service string, path string, method string) policy.Endpoint {
	return policy.Endpoint{Namespace: ns, Service: service, Path: path, Method: method}
}

func GetTargetElement(service string, paths []string) v1.TargetElement {
	return v1.TargetElement{ServiceName: service, Paths: paths}
}

func TargetGenerator(service []string, paths []string) []v1.TargetElement {
	target := make([]v1.TargetElement, 0)
	for _, svc := range service {
		target = append(target, GetTargetElement(svc, paths))
	}
	return target
}

func GetJwtPolicySpec(jwks string, target []v1.TargetElement) policy.Action {
	return policy.Action{KeySet: &mockKeySet{}, Type: policy.JWT}
}

func GetOidcPolicySpec(name string, target []v1.TargetElement) policy.Action {
	return policy.Action{Client: &mockClient{}, Type: policy.JWT}
}

func GetDefaultEndpoint() policy.Endpoint {
	return GetEndpoint(namespace, service, "*", "*")
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New())
}

func TestLocalStore_KeySet(t *testing.T) {
	store := New()
	assert.Nil(t, (&LocalStore{}).GetKeySet(jwksurl))
	assert.Nil(t, store.GetKeySet(jwksurl))
	store.AddKeySet(jwksurl, &mockKeySet{})
	assert.NotNil(t, store.GetKeySet(jwksurl))
}

func TestLocalStore_Client(t *testing.T) {
	store := New()
	assert.Nil(t, (&LocalStore{}).GetClient(clientname))
	assert.Nil(t, store.GetClient(clientname))
	store.AddClient(clientname, &mockClient{})
	assert.NotNil(t, store.GetClient(clientname))
}

func TestLocalStore_AuthServer(t *testing.T) {
	store := New()
	assert.Nil(t, (&LocalStore{}).GetAuthServer(clientname))
	store.AddAuthServer(servername, authserver.New(jwksurl))
	assert.Nil(t, store.GetAuthServer(clientname))
	assert.NotNil(t, store.GetAuthServer(servername))
}

func TestLocalStore_ApiPolicies(t *testing.T) {
	store := &LocalStore{}
	spec := GetJwtPolicySpec(jwksurl, TargetGenerator([]string{service}, nil))
	assert.Nil(t, store.GetApiPolicies(GetEndpoint(namespace, service, path, "")))
	store.SetApiPolicy(GetDefaultEndpoint(), spec)
	assert.Nil(t, store.GetApiPolicies(GetEndpoint(namespace, service, path, "")))
	assert.NotNil(t, store.GetApiPolicies(GetDefaultEndpoint()))
	store.DeleteApiPolicy(GetDefaultEndpoint(), spec)
	//assert.NotNil(t, store.GetApiPolicies(GetDefaultEndpoint()))
}

func TestLocalStore_WebPolicy(t *testing.T) {
	store := &LocalStore{}
	spec := GetOidcPolicySpec(jwksurl, TargetGenerator([]string{service}, nil))
	assert.Nil(t, store.GetWebPolicies(GetEndpoint(namespace, service, path, "")))
	store.SetWebPolicy(GetDefaultEndpoint(), spec)
	assert.Nil(t, store.GetWebPolicies(GetEndpoint(namespace, service, path, "")))
	assert.NotNil(t, store.GetWebPolicies(GetDefaultEndpoint()))
	store.DeleteWebPolicy(GetDefaultEndpoint(), spec)
	//assert.NotNil(t, store.GetWebPolicies(GetDefaultEndpoint()))
}

func TestLocalStore_PolicyMapping(t *testing.T) {
	store := &LocalStore{}
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
	store.AddPolicyMapping(samplePolicy, &policy.PolicyMapping{})
	assert.NotNil(t, store.GetPolicyMapping(samplePolicy))
	store.DeletePolicyMapping(samplePolicy)
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
}

type mockClient struct {
	server authserver.AuthorizationServer
}

func (m *mockClient) Name() string                                        { return "" }
func (m *mockClient) ID() string                                          { return "" }
func (m *mockClient) Secret() string                                      { return "" }
func (m *mockClient) AuthorizationServer() authserver.AuthorizationServer { return m.server }
func (m *mockClient) ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error) {
	return nil, nil
}

type mockKeySet struct{}

func (m *mockKeySet) PublicKeyURL() string                  { return "" }
func (m *mockKeySet) PublicKey(kid string) crypto.PublicKey { return nil }

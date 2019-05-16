package store

import (
	"github.com/stretchr/testify/assert"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"testing"
)

const (
	clientname = "clientname"
	servername = "servername"
	jwksurl = "http://mockserver"
	service = "service"
	namespace = "ns"
	path = "path"
	samplePolicy = "policy"
)

func GetEndpoint(ns string, service string, path string, method string) policy.Endpoint{
	return policy.Endpoint{Namespace: ns, Service: service, Path: path, Method: method}
}

func GetTargetElement(service string, paths []string) v1.TargetElement {
	return v1.TargetElement{ServiceName: service, Paths: paths}
}

func TargetGenerator(service []string, paths []string) []v1.TargetElement {
	target := make([]v1.TargetElement,0)
	for _, svc := range service {
		target = append(target, GetTargetElement(svc, paths))
	}
	return target
}

func GetJwtPolicySpec(jwks string, target []v1.TargetElement) v1.JwtPolicySpec {
	return v1.JwtPolicySpec{JwksURL: jwks, Target: target}
}

func GetOidcPolicySpec(name string, target []v1.TargetElement) v1.OidcPolicySpec {
	return v1.OidcPolicySpec{ClientName: name, Target: target}
}

func GetDefaultEndpoint() policy.Endpoint{
	return GetEndpoint(namespace, service,"*", "*")
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New())
}

func TestLocalStore_Client(t *testing.T) {
	store := New()
	assert.Nil(t, (&LocalStore{}).GetClient(clientname))
	assert.Nil(t, store.GetClient(clientname))
	store.AddClient(clientname, &client.Client{AuthServer:authserver.New(jwksurl)})
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
	assert.Equal(t, 0, len(store.GetApiPolicies(GetDefaultEndpoint())))
	store = &LocalStore{}
	store.SetApiPolicies(GetDefaultEndpoint(), []v1.JwtPolicySpec{spec, spec})
	result := store.GetApiPolicies(GetDefaultEndpoint())
	assert.NotNil(t, result)
	assert.Equal(t, 2, len(result))
}

func TestLocalStore_WebPolicy(t *testing.T) {
	store := &LocalStore{}
	spec := GetOidcPolicySpec(jwksurl, TargetGenerator([]string{service}, nil))
	assert.Nil(t, store.GetWebPolicies(GetEndpoint(namespace, service, path, "")))
	store.SetWebPolicy(GetDefaultEndpoint(), spec)
	assert.Nil(t, store.GetWebPolicies(GetEndpoint(namespace, service, path, "")))
	assert.NotNil(t, store.GetWebPolicies(GetDefaultEndpoint()))
	store.DeleteWebPolicy(GetDefaultEndpoint(), spec)
	assert.Equal(t, 0, len(store.GetWebPolicies(GetDefaultEndpoint())))
	store = &LocalStore{}
	store.SetWebPolicies(GetDefaultEndpoint(), []v1.OidcPolicySpec{spec, spec})
	result := store.GetWebPolicies(GetDefaultEndpoint())
	assert.NotNil(t, result)
	assert.Equal(t, 2, len(result))
}

func TestLocalStore_PolicyMapping(t *testing.T) {
	store := &LocalStore{}
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
	store.AddPolicyMapping(samplePolicy, &policy.PolicyMapping{})
	assert.NotNil(t, store.GetPolicyMapping(samplePolicy))
	store.DeletePolicyMapping(samplePolicy)
	assert.Nil(t, store.GetPolicyMapping(samplePolicy))
}
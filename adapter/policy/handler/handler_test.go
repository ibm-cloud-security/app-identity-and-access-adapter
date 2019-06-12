package handler

import (
	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store"
	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

type Type int

const (
	JWTPolicy Type = iota
	OIDCPolicy
	OIDCClient
	NONE
)

func GetObjctMeta() meta_v1.ObjectMeta {
	return meta_v1.ObjectMeta{Namespace: "sample", Name: "sample"}
}

func GetTypeMeta() meta_v1.TypeMeta {
	return meta_v1.TypeMeta{APIVersion: "v1", Kind: "JwtPolicy"}
}

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

func GetJwtPolicySpec(jwks string, target []v1.TargetElement) v1.JwtPolicySpec {
	return v1.JwtPolicySpec{JwksURL: jwks, Target: target}
}

func GetOidcPolicySpec(name string, target []v1.TargetElement) v1.OidcPolicySpec {
	return v1.OidcPolicySpec{ClientName: name, Target: target}
}

func GetOidcClientSpec(name string, id string, url string) v1.OidcClientSpec {
	return v1.OidcClientSpec{ClientName: name, ClientID: id, DiscoveryURL: url, ClientSecret: "", ClientSecretKey: "", ClientSecretName: ""}
}

func GetJwtPolicy(spec v1.JwtPolicySpec, objMeta meta_v1.ObjectMeta, typeMeta meta_v1.TypeMeta) v1.JwtPolicy {
	return v1.JwtPolicy{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func GetOidcPolicy(spec v1.OidcPolicySpec, objMeta meta_v1.ObjectMeta, typeMeta meta_v1.TypeMeta) v1.OidcPolicy {
	return v1.OidcPolicy{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func GetOidcClient(spec v1.OidcClientSpec, objMeta meta_v1.ObjectMeta, typeMeta meta_v1.TypeMeta) v1.OidcClient {
	return v1.OidcClient{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func JwtPolicyGenerator(targets []v1.TargetElement) v1.JwtPolicy {
	if len(targets) == 0 {
		targets = append(targets, GetTargetElement("samplesrv", []string{"/path"}))
	}
	jwtPolicySpec := GetJwtPolicySpec("https://sampleurl", targets)
	return GetJwtPolicy(jwtPolicySpec, GetObjctMeta(), GetTypeMeta())
}

func OidcPolicyGenerator(targets []v1.TargetElement) v1.OidcPolicy {
	if len(targets) == 0 {
		targets = append(targets, GetTargetElement("samplesrv", nil))
	}
	oidcPolicySpec := GetOidcPolicySpec("sampleoidc", targets)
	return GetOidcPolicy(oidcPolicySpec, GetObjctMeta(), GetTypeMeta())
}

func OidcClientGenerator(name string, id string, url string) v1.OidcClient {
	return GetOidcClient(GetOidcClientSpec(name, id, url), GetObjctMeta(), GetTypeMeta())
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New(store.New()))
}

func TestHandler_HandleAddEvent(t *testing.T) {
	testHandler := &CrdHandler{
		store: store.New(),
	}
	tests := []struct {
		objType  Type
		obj      interface{}
		initial  int
		expected int
		endpoint policy.Endpoint
	}{
		{
			objType:  JWTPolicy,
			obj:      JwtPolicyGenerator(TargetGenerator([]string{"samplesrv"}, nil)),
			initial:  0,
			expected: 1,
			endpoint: GetEndpoint("sample", "samplesrv", "*", "*"),
		},
		{
			objType:  OIDCPolicy,
			obj:      OidcPolicyGenerator(make([]v1.TargetElement, 0)),
			initial:  0,
			expected: 1,
			endpoint: GetEndpoint("sample", "samplesrv", "*", "*"),
		},
		{
			objType:  OIDCClient,
			obj:      OidcClientGenerator("name", "id", "url"),
			initial:  0,
			expected: 1,
			endpoint: GetEndpoint("sample", "samplesrv", "*", "*"),
		},
		{
			objType:  NONE,
			obj:      nil,
			initial:  0,
			expected: 0,
			endpoint: GetEndpoint("sample", "samplesrv", "*", "*"),
		},
	}
	for _, test := range tests {
		if test.objType == JWTPolicy {
			assert.NotNil(t, test.initial, testHandler.store.GetApiPolicies(test.endpoint))
		} else if test.objType == OIDCPolicy {
			assert.NotNil(t, test.initial, testHandler.store.GetWebPolicies(test.endpoint))
		}
		switch obj := test.obj.(type) {

		case v1.JwtPolicy:
			testHandler.HandleAddUpdateEvent(&obj)
			testHandler.HandleAddUpdateEvent(&obj)
		case v1.OidcPolicy:
			testHandler.HandleAddUpdateEvent(&obj)

		case v1.OidcClient:
			testHandler.HandleAddUpdateEvent(&obj)

		default:
			testHandler.HandleAddUpdateEvent(&obj)
		}
		if test.objType == JWTPolicy {
			assert.NotNil(t, test.expected, testHandler.store.GetApiPolicies(test.endpoint))
		} else if test.objType == OIDCPolicy {
			assert.NotNil(t, test.expected, testHandler.store.GetWebPolicies(test.endpoint))
		}

	}
}

func TestCrdHandler_HandleDeleteEvent(t *testing.T) {
	testHandler := &CrdHandler{
		store: store.New(),
	}
	tests := []struct {
		objType  Type
		obj      interface{}
		initial  int
		expected int
		endpoint policy.Endpoint
		crd      policy.CrdKey
	}{
		{
			objType:  JWTPolicy,
			obj:      JwtPolicyGenerator(make([]v1.TargetElement, 0)),
			initial:  0,
			expected: 0,
			endpoint: GetEndpoint("sample", "samplesrv", "*", "*"),
			crd:      policy.CrdKey{Id: "sample/sample"},
		},
		{
			objType:  JWTPolicy,
			obj:      JwtPolicyGenerator(make([]v1.TargetElement, 0)),
			initial:  0,
			expected: 0,
			endpoint: GetEndpoint("sample", "samplesrv", "/path", "*"),
			crd:      policy.CrdKey{Id: "sample/sample"},
		},
		{
			objType:  OIDCPolicy,
			obj:      OidcPolicyGenerator(TargetGenerator(make([]string, 0), nil)),
			initial:  0,
			expected: 0,
			endpoint: GetEndpoint("sample", "samplesrv", "/path", "*"),
			crd:      policy.CrdKey{Id: "sample/sample"},
		},
		{
			objType:  OIDCClient,
			obj:      OidcClientGenerator("name", "id", "url"),
			initial:  0,
			expected: 0,
			endpoint: GetEndpoint("sample", "samplesrv", "/path", "*"),
			crd:      policy.CrdKey{Id: "sample/sample"},
		},
	}
	for _, test := range tests {
		if test.objType == JWTPolicy {
			assert.NotNil(t, test.initial, testHandler.store.GetWebPolicies(test.endpoint))
		} else {
			assert.NotNil(t, test.expected, testHandler.store.GetWebPolicies(test.endpoint))
		}
		switch obj := test.obj.(type) {
		case v1.JwtPolicy:
			testHandler.HandleAddUpdateEvent(&obj)
			testHandler.HandleDeleteEvent(&obj)
			testHandler.HandleDeleteEvent(test.crd)
		case v1.OidcPolicy:
			testHandler.HandleAddUpdateEvent(&obj)
			testHandler.HandleDeleteEvent(test.crd)
		case v1.OidcClient:
			testHandler.HandleAddUpdateEvent(&obj)
			//testHandler.HandleDeleteEvent(crd)
		}
		if test.objType == JWTPolicy {
			assert.NotNil(t, test.expected, testHandler.store.GetApiPolicies(test.endpoint))
		} else {
			assert.NotNil(t, test.expected, testHandler.store.GetWebPolicies(test.endpoint))
		}

	}
}

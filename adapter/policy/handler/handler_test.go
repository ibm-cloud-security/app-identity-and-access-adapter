package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	storePolicy "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)

const (
	secretFromPlainText string = "secretFromPlainTextssd"
	jwksUrl             string = "https://sampleurl"
	ns string = "ns"
	service string = "service"
)

func getDefaultService() policy.Service{
	return policy.Service{Namespace:ns, Name: service}
}

func getPathConfig(exact string, prefix string, method string, policies []v1.PathPolicy) v1.PathConfig {
	return v1.PathConfig{
		Exact: exact,
		Prefix: prefix,
		Method: method,
		Policies: policies,
	}
}

func getPathConfigs(path v1.PathConfig) []v1.PathConfig{
	return []v1.PathConfig{ path,}
}

func getTargetElements(service string, paths []v1.PathConfig) v1.TargetElement {
	return v1.TargetElement{
		ServiceName: service,
		Paths: paths,
	}
}

func getEndpoint(service policy.Service, path string, method policy.Method) policy.Endpoint {
	return policy.Endpoint{
		Service: service,
		Path:    path,
		Method:  method,
	}
}

func getObjectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: "sample"}
}

func getObjectMetaWithName(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name}
}

func getTypeMeta() metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: "v1", Kind: "JwtPolicy"}
}

func getTargetElement(service string, paths []v1.PathConfig) v1.TargetElement {
	return v1.TargetElement{ServiceName: service, Paths: paths}
}

func getJwtConfigSpec(jwks string) v1.JwtConfigSpec {
	return v1.JwtConfigSpec{JwksURL: jwks}
}

func getPolicySpec(target []v1.TargetElement) v1.PolicySpec {
	return v1.PolicySpec{Target: target}
}

func getOidcConfigSpec(name string, id string, url string) v1.OidcConfigSpec {
	emptyRef := v1.ClientSecretRef{}
	return v1.OidcConfigSpec{ClientName: name, ClientID: id, DiscoveryURL: url, ClientSecret: secretFromPlainText, ClientSecretRef: emptyRef}
}

func getJwtConfig(spec v1.JwtConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.JwtConfig {
	return &v1.JwtConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func getPolicy(spec v1.PolicySpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.Policy {
	return &v1.Policy{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func getDefaultRoutePolicy() policy.RoutePolicy{
	return policy.NewRoutePolicy()
}

func getRoutePolicy(policyReference string) policy.RoutePolicy{
	return policy.RoutePolicy{
		PolicyReference: policyReference,
		Actions: getPathPolicy(),
	}
}

func getPathPolicy() []v1.PathPolicy{
	return []v1.PathPolicy{
		{
			PolicyType: policy.OIDC.String(),
			RedirectUri: jwksUrl,
			Config: "sampleoidc",
		},
	}
}

func getOidcConfig(spec v1.OidcConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.OidcConfig {
	return &v1.OidcConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func jwtConfigGenerator() *v1.JwtConfig {
	jwtPolicySpec := getJwtConfigSpec(jwksUrl)
	return getJwtConfig(jwtPolicySpec, getObjectMeta(), getTypeMeta())
}

func policyGenerator(targets []v1.TargetElement) *v1.Policy {
	if len(targets) == 0 {
		targets = append(targets, getTargetElement("samplesrv", nil))
	}
	oidcPolicySpec := getPolicySpec(targets)
	return getPolicy(oidcPolicySpec, getObjectMeta(), getTypeMeta())
}

func oidcConfigGenerator(name string, id string, url string) *v1.OidcConfig {
	return getOidcConfig(getOidcConfigSpec(name, id, url), getObjectMetaWithName(name), getTypeMeta())
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New(storePolicy.New(), fake.NewSimpleClientset()))
}

func TestHandler_HandleAddDeleteEvent_JwtConfig(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	testHandler.HandleAddUpdateEvent(jwtConfigGenerator()) // Add
	testHandler.HandleAddUpdateEvent(jwtConfigGenerator()) // Update policy
	key := "ns/sample"
	assert.Equal(t, testHandler.store.GetKeySet(key).PublicKeyURL(), jwksUrl)
	testHandler.HandleDeleteEvent(policy.CrdKey{
		Id: key,
		CrdType: v1.JWTCONFIG,
	})
	assert.Nil(t, testHandler.store.GetKeySet(key))
}

func TestHandler_HandleAddDeleteEvent_OidcConfig(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	policyName := "oidcconfig"
	key := "ns/" + policyName
	testHandler.HandleAddUpdateEvent(oidcConfigGenerator(policyName, "oidc", jwksUrl))
	assert.Equal(t, testHandler.store.GetClient(key).Secret(), secretFromPlainText)
	testHandler.HandleDeleteEvent(policy.CrdKey{
		Id: key,
		CrdType: v1.OIDCCONFIG,
	})
	assert.Nil(t, testHandler.store.GetKeySet(key))
	// invalid OidcConfig object
	testHandler.HandleAddUpdateEvent(getOidcConfig(v1.OidcConfigSpec{}, getObjectMetaWithName("sample"), getTypeMeta()))
	assert.Nil(t, testHandler.store.GetClient("ns/sample"))
}

func TestHandler_HandleAddDeleteEvent_Policy(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	targets := []v1.TargetElement{
		getTargetElements(service, getPathConfigs(getPathConfig("/path", "/paths", "GET", getPathPolicy()))),
	}
	testHandler.HandleAddUpdateEvent(policyGenerator(targets))
	key := "ns/sample"
	// getEndpoint(getDefaultService(), policy.GET, "/path")
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(),"/path", policy.GET)), getRoutePolicy(key))
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(),"/paths/*", policy.GET)), getRoutePolicy(key))
	// Invalid delete object passed test
	testHandler.HandleDeleteEvent(1)
	testHandler.HandleDeleteEvent(policy.CrdKey{
		Id: key,
		CrdType: v1.POLICY,
	})
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(),"/path", policy.GET)), getDefaultRoutePolicy())
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(),"/paths/*", policy.GET)), getDefaultRoutePolicy())
}
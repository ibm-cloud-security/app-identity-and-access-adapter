package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	k8sV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	storePolicy "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)

const (
	secretFromRef       string = "secretFromRef"
	secretFromPlainText string = "secretFromPlainTextssd"
	jwksUrl             string = "https://sampleurl"
)

func GetObjectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: "sample"}
}

func GetObjectMetaWithName(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name}
}

func GetTypeMeta() metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: "v1", Kind: "JwtPolicy"}
}

func GetTargetElement(service string, paths []v1.PathConfig) v1.TargetElement {
	return v1.TargetElement{ServiceName: service, Paths: paths}
}

func GetJwtConfigSpec(jwks string) v1.JwtConfigSpec {
	return v1.JwtConfigSpec{JwksURL: jwks}
}

func GetPolicySpec(target []v1.TargetElement) v1.PolicySpec {
	return v1.PolicySpec{Target: target}
}

func GetOidcConfigSpec(name string, id string, url string) v1.OidcConfigSpec {
	emptyRef := v1.ClientSecretRef{}
	return v1.OidcConfigSpec{ClientName: name, ClientID: id, DiscoveryURL: url, ClientSecret: secretFromPlainText, ClientSecretRef: emptyRef}
}

func GetJwtConfig(spec v1.JwtConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.JwtConfig {
	return &v1.JwtConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func GetPolicy(spec v1.PolicySpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.Policy {
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

func GetOidcConfig(spec v1.OidcConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.OidcConfig {
	return &v1.OidcConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func MockKubeSecret() *k8sV1.Secret {
	// create kube secret
	data := map[string][]byte{"secretKey": []byte(secretFromRef)}
	objData := metav1.ObjectMeta{Name: "mysecret"}
	return &k8sV1.Secret{Data: data, ObjectMeta: objData}
}

func JwtConfigGenerator() *v1.JwtConfig {
	jwtPolicySpec := GetJwtConfigSpec(jwksUrl)
	return GetJwtConfig(jwtPolicySpec, GetObjectMeta(), GetTypeMeta())
}

func PolicyGenerator(targets []v1.TargetElement) *v1.Policy {
	if len(targets) == 0 {
		targets = append(targets, GetTargetElement("samplesrv", nil))
	}
	oidcPolicySpec := GetPolicySpec(targets)
	return GetPolicy(oidcPolicySpec, GetObjectMeta(), GetTypeMeta())
}

func OidcConfigGenerator(name string, id string, url string) *v1.OidcConfig {
	return GetOidcConfig(GetOidcConfigSpec(name, id, url), GetObjectMetaWithName(name), GetTypeMeta())
}

func OidcConfigWithRef(name string, id string, url string, ref v1.ClientSecretRef) *v1.OidcConfig {
	return GetOidcConfig(
		v1.OidcConfigSpec{
			ClientName:      name,
			ClientID:        id,
			DiscoveryURL:    url,
			ClientSecret:    "",
			ClientSecretRef: ref,
		}, GetObjectMeta(), GetTypeMeta())
}

func OidcConfigNoSecret(name string, id string, url string) *v1.OidcConfig {
	return GetOidcConfig(
		v1.OidcConfigSpec{
			ClientName:   name,
			ClientID:     id,
			DiscoveryURL: url,
		}, GetObjectMeta(), GetTypeMeta())
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New(storePolicy.New(), fake.NewSimpleClientset()))
}

func TestGetClientSecret(t *testing.T) {
	testHandler := &CrdHandler{
		store:      storePolicy.New(),
		kubeClient: fake.NewSimpleClientset(),
	}
	tests := []struct {
		name   string
		obj    *v1.OidcConfig
		secret string
	}{
		{
			name:   "Plain text secret",
			obj:    GetOidcConfig(GetOidcConfigSpec("name", "id", "url"), GetObjectMeta(), GetTypeMeta()),
			secret: secretFromPlainText,
		},
		{
			name:   "No secret",
			obj:    OidcConfigNoSecret("name", "id", "url"),
			secret: "",
		},
		{
			name:   "secret from ref",
			obj:    OidcConfigWithRef("name", "id", "url", v1.ClientSecretRef{Name: "mysecret", Key: "secretKey"}),
			secret: secretFromRef,
		},
		{
			name:   "invalid ref name",
			obj:    OidcConfigWithRef("name", "id", "url", v1.ClientSecretRef{Name: "mysecret", Key: "invalidKey"}),
			secret: "",
		},
		{
			name:   "invalid ref key",
			obj:    OidcConfigWithRef("name", "id", "url", v1.ClientSecretRef{Name: "invalidName", Key: "secretKey"}),
			secret: "",
		},
		{
			name: "plaintext secret w/ invalid ref",
			obj: GetOidcConfig(
				v1.OidcConfigSpec{
					ClientName:      "name",
					ClientID:        "id",
					DiscoveryURL:    "url",
					ClientSecret:    secretFromPlainText,
					ClientSecretRef: v1.ClientSecretRef{Name: "mysecret", Key: ""}}, GetObjectMeta(), GetTypeMeta()),
			secret: secretFromPlainText,
		},
	}
	_, _ = testHandler.kubeClient.CoreV1().Secrets(ns).Create(MockKubeSecret())
	for _, test := range tests {
		test := test
		t.Run(test.name, func(st *testing.T) {
			st.Parallel()
			res := testHandler.getClientSecret(test.obj)
			assert.Equal(st, test.secret, res)
		})
	}
}

func TestHandler_HandleAddDeleteEvent_JwtConfig(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	testHandler.HandleAddUpdateEvent(JwtConfigGenerator()) // Add
	testHandler.HandleAddUpdateEvent(JwtConfigGenerator()) // Update policy
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
	testHandler.HandleAddUpdateEvent(OidcConfigGenerator(policyName, "oidc", jwksUrl))
	assert.Equal(t, testHandler.store.GetClient(key).Secret(), secretFromPlainText)
	testHandler.HandleDeleteEvent(policy.CrdKey{
		Id: key,
		CrdType: v1.OIDCCONFIG,
	})
	assert.Nil(t, testHandler.store.GetKeySet(key))
	// invalid OidcConfig object
	testHandler.HandleAddUpdateEvent(GetOidcConfig(v1.OidcConfigSpec{}, GetObjectMetaWithName("sample"), GetTypeMeta()))
	assert.Nil(t, testHandler.store.GetClient("ns/sample"))
}

func TestHandler_HandleAddDeleteEvent_Policy(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	targets := []v1.TargetElement{
		getTargetElements(service, getPathConfigs(getPathConfig("/path", "/paths", "GET", getPathPolicy()))),
	}
	testHandler.HandleAddUpdateEvent(PolicyGenerator(targets))
	key := "ns/sample"
	// getEndpoint(getDefaultService(), policy.GET, "/path")
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/path")), getRoutePolicy(key))
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/paths/*")), getRoutePolicy(key))
	testHandler.HandleDeleteEvent(policy.CrdKey{
		Id: key,
		CrdType: v1.POLICY,
	})
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/path")), getDefaultRoutePolicy())
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/paths/*")), getDefaultRoutePolicy())
}
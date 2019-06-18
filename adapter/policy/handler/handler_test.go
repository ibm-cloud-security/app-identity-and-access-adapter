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
	return metav1.ObjectMeta{Namespace: "sample", Name: "sample"}
}

func GetObjectMetaWithName(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: name, Name: name}
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
	_, _ = testHandler.kubeClient.CoreV1().Secrets("sample").Create(MockKubeSecret())
	for _, test := range tests {
		test := test
		t.Run(test.name, func(st *testing.T) {
			st.Parallel()
			res := testHandler.getClientSecret(test.obj)
			assert.Equal(st, test.secret, res)
		})
	}
}

func TestHandler_HandleAddEvent_JwtConfig(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	testHandler.HandleAddUpdateEvent(JwtConfigGenerator()) // Add
	testHandler.HandleAddUpdateEvent(JwtConfigGenerator()) // Update policy
	assert.Equal(t, testHandler.store.GetKeySet("sample.sample").PublicKeyURL(), jwksUrl)
}

func TestHandler_HandleAddEvent_OidcConfig(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	policyName := "oidcconfig"
	testHandler.HandleAddUpdateEvent(OidcConfigGenerator(policyName, "oidc", jwksUrl))
	client := testHandler.store.GetClient(policyName + "." + policyName)
	assert.Equal(t, client.Secret(), secretFromPlainText)
	// invalid OidcConfig object
	testHandler.HandleAddUpdateEvent(GetOidcConfig(v1.OidcConfigSpec{}, GetObjectMetaWithName("sample"), GetTypeMeta()))
	assert.Nil(t, testHandler.store.GetClient("sample.sample"))
}

func TestHandler_HandleAddEvent_Policy(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
	}
	targets := []v1.TargetElement{
		getTargetElements(service, getPathConfigs(getPathConfig("/path", "/paths", "GET", getDefaultPathPolicy()))),
	}
	testHandler.HandleAddUpdateEvent(PolicyGenerator(targets))
	// getEndpoint(getDefaultService(), policy.GET, "/path")
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/path")), getDefaultPathPolicy())
	assert.Equal(t, testHandler.store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/paths/*")), getDefaultPathPolicy())
}

/*
func TestCrdHandler_HandleDeleteEvent(t *testing.T) {
	testHandler := &CrdHandler{
		store: storePolicy.New(),
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


 */
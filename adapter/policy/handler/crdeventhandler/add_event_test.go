package crdeventhandler


import (
	"testing"

	"github.com/stretchr/testify/assert"
	k8sV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
	storePolicy "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy/store/policy"
)

const (
	jwksUrl             string = "https://sampleurl"
	ns  string = "ns"
	service string= "service"
	secretFromRef       string = "secretFromRef"
	secretFromPlainText string = "secretFromPlainTextssd"
)

func getDefaultService() policy.Service{
	return policy.Service{Namespace:ns, Name: service}
}

func getDefaultPathPolicy() []v1.PathPolicy{
	return []v1.PathPolicy{}
}

func getObjectMetaWithName(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name}
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

func getJwtConfig(spec v1.JwtConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.JwtConfig {
	return &v1.JwtConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func getPolicy(spec v1.PolicySpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.Policy {
	return &v1.Policy{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func getObjectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: "sample"}
}

func getTypeMeta() metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: "v1", Kind: "JwtPolicy"}
}

func mockKubeSecret() *k8sV1.Secret {
	// create kube secret
	data := map[string][]byte{"secretKey": []byte(secretFromRef)}
	objData := metav1.ObjectMeta{Name: "mysecret"}
	return &k8sV1.Secret{Data: data, ObjectMeta: objData}
}

func getOidcConfigSpec(name string, id string, url string) v1.OidcConfigSpec {
	emptyRef := v1.ClientSecretRef{}
	return v1.OidcConfigSpec{ClientName: name, ClientID: id, DiscoveryURL: url, ClientSecret: secretFromPlainText, ClientSecretRef: emptyRef}
}

func oidcConfigWithRef(name string, id string, url string, ref v1.ClientSecretRef) *v1.OidcConfig {
	return getOidcConfig(
		v1.OidcConfigSpec{
			ClientName:      name,
			ClientID:        id,
			DiscoveryURL:    url,
			ClientSecret:    "",
			ClientSecretRef: ref,
		}, getObjectMeta(), getTypeMeta())
}

func oidcConfigNoSecret(name string, id string, url string) *v1.OidcConfig {
	return getOidcConfig(
		v1.OidcConfigSpec{
			ClientName:   name,
			ClientID:     id,
			DiscoveryURL: url,
		}, getObjectMeta(), getTypeMeta())
}

func getOidcConfig(spec v1.OidcConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.OidcConfig {
	return &v1.OidcConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
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


func TestGetClientSecret(t *testing.T) {
	tests := []struct {
		name   string
		obj    *v1.OidcConfig
		secret string
	}{
		{
			name:   "Plain text secret",
			obj:    getOidcConfig(getOidcConfigSpec("name", "id", "url"), getObjectMeta(), getTypeMeta()),
			secret: secretFromPlainText,
		},
		{
			name:   "No secret",
			obj:    oidcConfigNoSecret("name", "id", "url"),
			secret: "",
		},
		{
			name:   "secret from ref",
			obj:    oidcConfigWithRef("name", "id", "url", v1.ClientSecretRef{Name: "mysecret", Key: "secretKey"}),
			secret: secretFromRef,
		},
		{
			name:   "invalid ref name",
			obj:    oidcConfigWithRef("name", "id", "url", v1.ClientSecretRef{Name: "mysecret", Key: "invalidKey"}),
			secret: "",
		},
		{
			name:   "invalid ref key",
			obj:    oidcConfigWithRef("name", "id", "url", v1.ClientSecretRef{Name: "invalidName", Key: "secretKey"}),
			secret: "",
		},
		{
			name: "plaintext secret w/ invalid ref",
			obj: getOidcConfig(
				v1.OidcConfigSpec{
					ClientName:      "name",
					ClientID:        "id",
					DiscoveryURL:    "url",
					ClientSecret:    secretFromPlainText,
					ClientSecretRef: v1.ClientSecretRef{Name: "mysecret", Key: ""}}, getObjectMeta(), getTypeMeta()),
			secret: secretFromPlainText,
		},
	}
	kubeclient := fake.NewSimpleClientset()
	kubeclient.CoreV1().Secrets(ns).Create(mockKubeSecret())
	for _, test := range tests {
		test := test
		t.Run(test.name, func(st *testing.T) {
			st.Parallel()
			res := GetClientSecret(test.obj, kubeclient)
			assert.Equal(st, test.secret, res)
		})
	}
}

func TestHandler_JwtConfigAddEventHandler(t *testing.T) {
	store:= storePolicy.New()
	handler := GetAddEventHandler(jwtConfigGenerator(), store, fake.NewSimpleClientset())
	handler.HandleAddUpdateEvent()
	key := "ns/sample"
	assert.Equal(t, store.GetKeySet(key).PublicKeyURL(), jwksUrl)
}

func TestHandler_OidcConfigAddEventHandler(t *testing.T) {
	store:= storePolicy.New()
	policyName := "oidcconfig"
	key := "ns/" + policyName
	handler := GetAddEventHandler(oidcConfigGenerator(policyName, "oidc", jwksUrl), store, fake.NewSimpleClientset())
	handler.HandleAddUpdateEvent()
	assert.Equal(t, store.GetClient(key).Secret(), secretFromPlainText)
}

func TestHandler_PolicyAddEventHandler(t *testing.T) {
	store:= storePolicy.New()
	key := "ns/sample"
	targets := []v1.TargetElement{
		getTargetElements(service, getPathConfigs(getPathConfig("/path", "/paths", "GET", getPathPolicy()))),
	}
	handler := GetAddEventHandler(policyGenerator(targets), store, fake.NewSimpleClientset())
	handler.HandleAddUpdateEvent()
	assert.Equal(t, store.GetPolicies(getEndpoint(getDefaultService(), policy.GET,"/path")), getRoutePolicy(key))
	assert.Equal(t, store.GetPolicies(getEndpoint(getDefaultService(), policy.GET,"/paths/*")), getRoutePolicy(key))
}

func TestHandler_InvalidObject(t *testing.T) {
	store:= storePolicy.New()
	handler := GetAddEventHandler(1, store, fake.NewSimpleClientset())
	assert.Nil(t, handler)
}
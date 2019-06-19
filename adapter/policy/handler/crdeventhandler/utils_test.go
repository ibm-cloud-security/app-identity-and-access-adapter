package crdeventhandler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	k8sV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

const (
	ns   = "ns"
	service = "service"
	secretFromRef       string = "secretFromRef"
	secretFromPlainText string = "secretFromPlainTextssd"
)

func getDefaultService() policy.Service{
	return policy.Service{Namespace:ns, Name: service}
}

func getDefaultPathPolicy() []v1.PathPolicy{
	return []v1.PathPolicy{}
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

type output struct {
	policies []policy.PolicyMapping
	total int
}

func TestParsedTarget(t *testing.T) {
	tests := [] struct{
		name string
		targets  []v1.TargetElement
		output output
	} {
		{
			name: "No exact/prefix provided",
			targets: []v1.TargetElement{
				getTargetElements(service, getPathConfigs(getPathConfig("", "", "", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("", "", "GET", getDefaultPathPolicy()))),
			},
			output: output{
				total: 2,
				policies: []policy.PolicyMapping{
					{
						Endpoint: getEndpoint(getDefaultService(), policy.ALL, "/*"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/*"),
						Actions:  getDefaultPathPolicy(),
					},
				},
			},
		},
		{
			name: "exact path test",
			targets: []v1.TargetElement{
				getTargetElements(service, getPathConfigs(getPathConfig("/", "", "", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("/path", "", "GET", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("/path1/", "", "GET", getDefaultPathPolicy()))),
			},
			output: output{
				total: 3,
				policies: []policy.PolicyMapping{
					{
						Endpoint: getEndpoint(getDefaultService(), policy.ALL, "/"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path1"),
						Actions:  getDefaultPathPolicy(),
					},
				},
			},
		},
		{
			name: "prefix path test",
			targets: []v1.TargetElement{
				getTargetElements(service, getPathConfigs(getPathConfig("", "/", "", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("", "/path", "GET", getDefaultPathPolicy()))),
				getTargetElements(service, getPathConfigs(getPathConfig("", "/path1/", "GET", getDefaultPathPolicy()))),
			},
			output: output{
				total: 3,
				policies: []policy.PolicyMapping{
					{
						Endpoint: getEndpoint(getDefaultService(), policy.ALL, "/*"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path/*"),
						Actions:  getDefaultPathPolicy(),
					},
					{
						Endpoint: getEndpoint(getDefaultService(), policy.GET, "/path1/*"),
						Actions:  getDefaultPathPolicy(),
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(st *testing.T) {
			st.Parallel()
			result := ParseTarget(test.targets, ns)
			assert.Equal(t, len(result), test.output.total)
			if !reflect.DeepEqual(result, test.output.policies) {
				assert.Fail(t, fmt.Sprintf("expected out to have value %v, got %v", test.output.policies, result))
			}
		})
	}
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
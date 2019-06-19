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
	jwksUrl             string = "https://sampleurl"
	ns string = "ns"
)

func getObjectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: "sample"}
}

func getTypeMeta() metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: "v1", Kind: "JwtPolicy"}
}


func getJwtConfigSpec(jwks string) v1.JwtConfigSpec {
	return v1.JwtConfigSpec{JwksURL: jwks}
}

func getJwtConfig(spec v1.JwtConfigSpec, objMeta metav1.ObjectMeta, typeMeta metav1.TypeMeta) *v1.JwtConfig {
	return &v1.JwtConfig{Spec: spec, ObjectMeta: objMeta, TypeMeta: typeMeta}
}

func jwtConfigGenerator() *v1.JwtConfig {
	jwtPolicySpec := getJwtConfigSpec(jwksUrl)
	return getJwtConfig(jwtPolicySpec, getObjectMeta(), getTypeMeta())
}

func TestNew(t *testing.T) {
	assert.NotNil(t, New(storePolicy.New(), fake.NewSimpleClientset()))
}

func TestHandler_HandleEventTest(t *testing.T) {
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
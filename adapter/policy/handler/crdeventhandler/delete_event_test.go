package crdeventhandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	storePolicy "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)

func TestHandler_JwtConfigDeleteEventHandler(t *testing.T) {
	store := storePolicy.New()
	handler := GetAddEventHandler(jwtConfigGenerator(), store, fake.NewSimpleClientset())
	handler.HandleAddUpdateEvent()
	key := "ns/sample"
	assert.Equal(t, store.GetKeySet(key).PublicKeyURL(), jwksUrl)
	deleteHandler := GetDeleteEventHandler(policy.CrdKey{ID: key, CrdType: v1.JWTCONFIG}, store)
	deleteHandler.HandleDeleteEvent()
	assert.Nil(t, store.GetKeySet(key))
}

func TestHandler_OidcConfigDeleteEventHandler(t *testing.T) {
	store := storePolicy.New()
	policyName := "oidcconfig"
	key := "ns/" + policyName
	handler := GetAddEventHandler(oidcConfigGenerator(policyName, "oidc", jwksUrl), store, fake.NewSimpleClientset())
	handler.HandleAddUpdateEvent()
	assert.Equal(t, store.GetClient(key).Secret(), secretFromPlainText)
	deleteHandler := GetDeleteEventHandler(policy.CrdKey{ID: key, CrdType: v1.OIDCCONFIG}, store)
	deleteHandler.HandleDeleteEvent()
	assert.Nil(t, store.GetClient(key))
}

func TestHandler_PolicyDeleteEventHandler(t *testing.T) {
	store := storePolicy.New()
	key := "ns/sample"
	targets := []v1.TargetElement{
		getTargetElements(service, getPathConfigs(getPathConfig("/path", "/paths", "GET", getPathPolicy()))),
	}
	handler := GetAddEventHandler(policyGenerator(targets), store, fake.NewSimpleClientset())
	handler.HandleAddUpdateEvent()
	assert.Equal(t, store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/path")), getRoutePolicy(key))
	assert.Equal(t, store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/paths/*")), getRoutePolicy(key))
	deleteHandler := GetDeleteEventHandler(policy.CrdKey{ID: key, CrdType: v1.POLICY}, store)
	deleteHandler.HandleDeleteEvent()
	assert.Equal(t, store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/path")), getDefaultRoutePolicy())
	assert.Equal(t, store.GetPolicies(getEndpoint(getDefaultService(), policy.GET, "/paths/*")), getDefaultRoutePolicy())

}

func TestHandler_InvalidInputObject(t *testing.T) {
	store := storePolicy.New()
	handler := GetDeleteEventHandler(policy.CrdKey{ID: "key", CrdType: 5}, store)
	assert.Nil(t, handler)
}

package handler

import (
	"github.com/stretchr/testify/assert"
	v1 "ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/store"
	"istio.io/istio/pkg/log"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestHandler_HandleAddEvent(t *testing.T) {
	testHandler := &CrdHandler{
		store: store.New(),
	}
	endpoint := policy.Endpoint{Namespace: "sample", Service: "samplesrv", Path: "*", Method: "*"}
	target := make([]v1.TargetElement, 0)
	target = append(target, v1.TargetElement{ServiceName: "samplesrv", Paths: nil})
	jwtPolicySpec := v1.JwtPolicySpec{JwksURL: "https://sampleurl", Target: target}
	jwtPolicy := v1.JwtPolicy{Spec: jwtPolicySpec, ObjectMeta: meta_v1.ObjectMeta{Namespace: "sample"}, TypeMeta: meta_v1.TypeMeta{APIVersion: "v1", Kind: "JwtPolicy"}}
	assert.Equal(t, 0, len(testHandler.store.GetApiPolicies(endpoint)))
	testHandler.HandleAddUpdateEvent(&jwtPolicy)
	//log.Debugf("Object of type : %d", len(testManager.apiPolicies))
	log.Debugf("Object of type : %v", testHandler.store.GetApiPolicies(endpoint))
	assert.Equal(t, 1, len(testHandler.store.GetApiPolicies(endpoint)))

}

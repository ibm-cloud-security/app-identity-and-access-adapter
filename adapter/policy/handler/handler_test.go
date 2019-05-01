package handler

import (
	"github.com/stretchr/testify/assert"
	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/client"
	v1 "ibmcloudappid/adapter/pkg/apis/policies/v1"
	"istio.io/istio/pkg/log"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestManager_HandleAddEvent(t *testing.T) {
	testManager := &Manager{
		clients:     make(map[string]*client.Client),
		authservers: make(map[string]authserver.AuthorizationServer),
		apiPolicies: make(map[endpoint][]v1.JwtPolicySpec),
		webPolicies: make(map[endpoint][]v1.OidcPolicySpec),
		policyMappings: make(map[string]PolicyMapping),
	}
	target := make([]v1.TargetElement, 0)
	target = append(target, v1.TargetElement{ServiceName: "samplesrv", Paths: nil})
	jwtPolicySpec := v1.JwtPolicySpec{JwksURL: "https://sampleurl", Target: target}
	jwtPolicy := v1.JwtPolicy{Spec:jwtPolicySpec,ObjectMeta: meta_v1.ObjectMeta{Namespace:"sample"},TypeMeta: meta_v1.TypeMeta{APIVersion:"v1",Kind: "JwtPolicy"}}
	assert.Equal(t, 0, len(testManager.apiPolicies))
	testManager.HandleAddUpdateEvent(&jwtPolicy)
	//log.Debugf("Object of type : %d", len(testManager.apiPolicies))
	log.Debugf("Object of type : %v", testManager.apiPolicies)
	assert.Equal(t, 1, len(testManager.apiPolicies))

}

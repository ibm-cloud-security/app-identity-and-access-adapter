package engine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"ibmcloudappid/adapter/authserver/keyset"
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/store"
	"istio.io/istio/mixer/template/authorization"
)

func TestNew(t *testing.T) {
	tests := []struct {
		store store.PolicyStore
		err   error
	}{
		{
			store: nil,
			err:   errors.New("could not create policy engine using undefined store"),
		},
		{
			store: store.New(),
			err:   nil,
		},
	}
	for _, test := range tests {
		result, err := New(test.store)
		if test.err != nil {
			assert.Nil(t, result)
			assert.Equal(t, test.err, err)
		} else {
			assert.Equal(t, test.store, result.(*engine).store)
		}
	}
}

func TestEvaluateJWTPolicies(t *testing.T) {
	tests := []struct {
		input               *authorization.ActionMsg
		jwtpolicies         []v1.JwtPolicySpec
		endpoints           []policy.Endpoint
		expectedAction      policy.Type
		expectedPolicyCount int
		err                 error
	}{
		{
			// 1 - err - missing authorization server
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			jwtpolicies: []v1.JwtPolicySpec{
				v1.JwtPolicySpec{JwksURL: "another serverurl"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:      policy.NONE,
			expectedPolicyCount: 0,
			err:                 errors.New("missing authentication server : cannot authenticate user"),
		},
		{
			// 1 - no policies
			input:               generateActionMessage("", "", "", ""),
			jwtpolicies:         []v1.JwtPolicySpec{},
			endpoints:           []policy.Endpoint{},
			expectedAction:      policy.NONE,
			expectedPolicyCount: 0,
			err:                 nil,
		},
		{
			// 2 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			jwtpolicies: []v1.JwtPolicySpec{
				v1.JwtPolicySpec{JwksURL: "serverurl"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:      policy.JWT,
			expectedPolicyCount: 1,
			err:                 nil,
		},
		{
			// 3 - Diff method
			input: generateActionMessage("namespace", "svc", "/path", "GET"),
			jwtpolicies: []v1.JwtPolicySpec{
				v1.JwtPolicySpec{JwksURL: "serverurl"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:      policy.NONE,
			expectedPolicyCount: 0,
			err:                 nil,
		},
		{
			// 4 - Generic Method
			input: generateActionMessage("namespace", "svc", "/path", "OTHER"),
			jwtpolicies: []v1.JwtPolicySpec{
				v1.JwtPolicySpec{JwksURL: "serverurl"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "*"),
			},
			expectedAction:      policy.JWT,
			expectedPolicyCount: 1,
			err:                 nil,
		},
		{
			// 5- Generic Path / Method
			input: generateActionMessage("namespace", "svc", "/path", "GET"),
			jwtpolicies: []v1.JwtPolicySpec{
				v1.JwtPolicySpec{JwksURL: "serverurl"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "*", "*"),
			},
			expectedAction:      policy.JWT,
			expectedPolicyCount: 1,
			err:                 nil,
		},
	}

	for i, test := range tests {
		/// Create new engine
		store := store.New().(*store.LocalStore)
		store.AddAuthServer("serverurl", &mockAuthServer{})
		for _, ep := range test.endpoints {
			store.SetApiPolicies(ep, test.jwtpolicies)
		}
		eng := &engine{store: store}
		result, err := eng.Evaluate(test.input)

		// Result
		if test.err != nil {
			assert.Equal(t, test.err, err, "Expected to receive error : "+fmt.Sprintf("%v", i))
		} else {
			assert.Equal(t, test.expectedPolicyCount, len(result.Policies), "Wrong number of policies returned for test case : "+fmt.Sprintf("%v", i))
			assert.Equal(t, test.expectedAction, result.Type, "Unexpected action type returned for test case : "+fmt.Sprintf("%v", i))
		}
	}
}

func genEndpoint(ns string, svc string, path string, method string) policy.Endpoint {
	return policy.Endpoint{
		Namespace: ns,
		Service:   svc,
		Path:      path,
		Method:    method,
	}
}

func generateActionMessage(ns string, svc string, path string, method string) *authorization.ActionMsg {
	return &authorization.ActionMsg{
		Namespace: ns,
		Service:   svc,
		Path:      path,
		Method:    method,
	}
}

type mockAuthServer struct{}

func (m *mockAuthServer) KeySet() keyset.KeySet { return nil }

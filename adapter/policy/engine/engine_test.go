package engine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"github.com/stretchr/testify/assert"
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
		input               *authnz.TargetMsg
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

func TestEvaluateOIDCPolicies(t *testing.T) {
	tests := []struct {
		input               *authnz.TargetMsg
		oidcpolicies        []v1.OidcPolicySpec
		endpoints           []policy.Endpoint
		expectedAction      policy.Type
		expectedPolicyCount int
		err                 error
	}{
		{
			// 0 - No policies
			input:               generateActionMessage("namespace", "svc", "/path", "POST"),
			oidcpolicies:        []v1.OidcPolicySpec{},
			endpoints:           []policy.Endpoint{},
			expectedAction:      policy.NONE,
			expectedPolicyCount: 0,
			err:                 nil,
		},
		{
			// 1 - Error
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			oidcpolicies: []v1.OidcPolicySpec{
				v1.OidcPolicySpec{ClientName: "unknown_client"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:      policy.OIDC,
			expectedPolicyCount: 0,
			err:                 errors.New("missing OIDC client : cannot authenticate user"),
		},
		{
			// 1 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			oidcpolicies: []v1.OidcPolicySpec{
				v1.OidcPolicySpec{ClientName: "client"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:      policy.OIDC,
			expectedPolicyCount: 1,
			err:                 nil,
		},
	}

	for i, test := range tests {
		/// Create new engine
		store := store.New().(*store.LocalStore)
		store.AddClient("client", &client.Client{AuthServer: &mockAuthServer{}})
		eng := &engine{store: store}
		for _, ep := range test.endpoints {
			store.SetWebPolicies(ep, test.oidcpolicies)
		}
		// Result
		result, err := eng.Evaluate(test.input)
		if test.err != nil {
			assert.Equal(t, test.err, err, "Expected to receive error : "+fmt.Sprintf("%v", i))
		} else {
			assert.Equal(t, test.expectedPolicyCount, len(result.Policies), "Wrong number of policies returned for test case : "+fmt.Sprintf("%v", i))
			assert.Equal(t, test.expectedAction, result.Type, "Unexpected action type returned for test case : "+fmt.Sprintf("%v", i))
		}
	}
}

func TestEvaluateJWTAndOIDCPolicies(t *testing.T) {
	tests := []struct {
		input               *authnz.TargetMsg
		jwtpolicies         []v1.JwtPolicySpec
		oidcpolicies        []v1.OidcPolicySpec
		endpoints           []policy.Endpoint
		expectedAction      policy.Type
		expectedPolicyCount int
		err                 error
	}{
		{
			// 1 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			jwtpolicies: []v1.JwtPolicySpec{
				v1.JwtPolicySpec{JwksURL: "serverurl"},
			},
			oidcpolicies: []v1.OidcPolicySpec{
				v1.OidcPolicySpec{ClientName: "client"},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:      policy.NONE,
			expectedPolicyCount: 0,
			err:                 errors.New("conflicting OIDC and JWT policies"),
		},
	}

	for i, test := range tests {
		/// Create new engine
		store := store.New().(*store.LocalStore)
		store.AddAuthServer("serverurl", &mockAuthServer{})
		store.AddClient("client", &client.Client{AuthServer: store.GetAuthServer("serverurl")})
		eng := &engine{store: store}
		for _, ep := range test.endpoints {
			store.SetApiPolicies(ep, test.jwtpolicies)
			store.SetWebPolicies(ep, test.oidcpolicies)
		}
		// Result
		result, err := eng.Evaluate(test.input)
		if test.err != nil {
			assert.Equal(t, test.err.Error(), err.Error(), "Expected to receive error : "+fmt.Sprintf("%v", i))
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

func generateActionMessage(ns string, svc string, path string, method string) *authnz.TargetMsg {
	return &authnz.TargetMsg{
		Namespace: ns,
		Service:   svc,
		Path:      path,
		Method:    method,
	}
}

type mockAuthServer struct{}

func (m *mockAuthServer) KeySet() keyset.KeySet { return nil }

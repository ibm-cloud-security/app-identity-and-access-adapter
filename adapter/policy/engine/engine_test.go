package engine

import (
	"errors"
	"testing"

	policy2 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"

	"github.com/stretchr/testify/assert"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
)

func TestNew(t *testing.T) {
	tests := []struct {
		store policy2.PolicyStore
		err   error
	}{
		{
			store: nil,
			err:   errors.New("could not create policy engine using undefined store"),
		},
		{
			store: policy2.New(),
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
		input             *authnz.TargetMsg
		actions           []policy.Action
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 0 - no policies
			input:             generateActionMessage("", "", "", ""),
			actions:           nil,
			endpoints:         []policy.Endpoint{},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 1 - 1 policy
			input:   generateActionMessage("namespace", "svc", "/path", "POST"),
			actions: genJWTActionArray(),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 2 - logout
			input:   generateActionMessage("namespace", "svc", "/path/oidc/logout", "POST"),
			actions: genJWTActionArray(),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 3 - callback
			input:   generateActionMessage("namespace", "svc", "/path/oidc/callback", "POST"),
			actions: genJWTActionArray(),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 4 - Diff method
			input:   generateActionMessage("namespace", "svc", "/path", "GET"),
			actions: genJWTActionArray(),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 5 - Generic Method
			input:   generateActionMessage("namespace", "svc", "/path", "OTHER"),
			actions: genJWTActionArray(),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "*"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 6 - Generic Path / Method
			input:   generateActionMessage("namespace", "svc", "/path", "GET"),
			actions: genJWTActionArray(),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/*", "ALL"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
	}

	for _, ts := range tests {
		/// Create new engine
		test := ts
		t.Run("Engine", func(t *testing.T) {
			store := policy2.New().(*policy2.LocalStore)
			store.AddClient("name", fake.NewClient(nil))
			store.AddKeySet("serverurl", &fake.KeySet{})
			for _, ep := range test.endpoints {
				if test.actions != nil {
					store.SetPolicies(ep, test.actions)
				}

			}
			eng := &engine{store: store}
			result, err := eng.Evaluate(test.input)

			// Result
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else {
				assert.Equal(t, test.expectedRuleCount, len(result.Rules))
				assert.Equal(t, test.expectedAction, result.Type)
			}
		})
	}
}

func TestEvaluateOIDCPolicies(t *testing.T) {
	tests := []struct {
		input             *authnz.TargetMsg
		actions           []policy.Action
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 0 - No policies
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			actions: []policy.Action{
				{
					Type:       policy.OIDC,
					Client:     &fake.Client{},
					ClientName: "name",
				},
			},
			endpoints:         []policy.Endpoint{},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 1 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			actions: []policy.Action{
				{
					Type:       policy.OIDC,
					Client:     &fake.Client{},
					ClientName: "name",
				},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.OIDC,
			expectedRuleCount: 1,
			err:               nil,
		},
	}

	for _, test := range tests {
		t.Run("oidc test", func(t *testing.T) {
			/// Create new engine
			store := policy2.New().(*policy2.LocalStore)
			store.AddClient("client", &fake.Client{Server: &fake.AuthServer{}})
			eng := &engine{store: store}
			for _, ep := range test.endpoints {
				if test.actions != nil {
					store.SetPolicies(ep, test.actions)
				}

			}
			// Result
			result, err := eng.Evaluate(test.input)
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else {
				assert.Equal(t, test.expectedRuleCount, len(result.Rules))
				assert.Equal(t, test.expectedAction, result.Type)
			}
		})
	}
}

func genEndpoint(ns string, svc string, path string, method string) policy.Endpoint {
	return policy.Endpoint{
		Service: policy.Service{
			Namespace: ns,
			Name:      svc,
		},
		Path:   path,
		Method: policy.NewMethod(method),
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

func genJWTActionArray() []policy.Action {
	return []policy.Action{
		{
			Type:   policy.JWT,
			KeySet: &fake.KeySet{},
		},
	}
}

package engine

import (
	"errors"
	"fmt"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
	"github.com/prometheus/common/log"
	"testing"

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
		input             *authnz.TargetMsg
		action            *policy.Action
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 1 - no policies
			input:             generateActionMessage("", "", "", ""),
			action:            nil,
			endpoints:         []policy.Endpoint{},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 2 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			action: &policy.Action{
				Type:   policy.JWT,
				KeySet: &fake.KeySet{},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 3 - Diff method
			input: generateActionMessage("namespace", "svc", "/path", "GET"),
			action: &policy.Action{
				Type:   policy.JWT,
				KeySet: &fake.KeySet{},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 4 - Generic Method
			input: generateActionMessage("namespace", "svc", "/path", "OTHER"),
			action: &policy.Action{
				Type:   policy.JWT,
				KeySet: &fake.KeySet{},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "*"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 5- Generic Path / Method
			input: generateActionMessage("namespace", "svc", "/path", "GET"),
			action: &policy.Action{
				Type:   policy.JWT,
				KeySet: &fake.KeySet{},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "*", "*"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 0,
			err:               nil,
		},
	}

	for i, test := range tests {
		/// Create new engine
		store := store.New().(*store.LocalStore)
		store.AddAuthServer("serverurl", &fake.AuthServer{})
		store.AddKeySet("serverurl", &fake.KeySet{})
		for _, ep := range test.endpoints {
			log.Info(ep) //so it wont throw an error
			if test.action != nil {
				store.SetApiPolicy(ep, *test.action)
			}

		}
		eng := &engine{store: store}
		result, err := eng.Evaluate(test.input)

		// Result
		if test.err != nil {
			assert.Equal(t, test.err, err, "Expected to receive error : "+fmt.Sprintf("%v", i))
		} else {
			assert.Equal(t, test.expectedRuleCount, len(result.Rules), "Wrong number of rules returned for tests case : "+fmt.Sprintf("%v", i))
			assert.Equal(t, test.expectedAction, result.Type, "Unexpected action type returned for tests case : "+fmt.Sprintf("%v", i))
		}
	}
}

func TestEvaluateOIDCPolicies(t *testing.T) {
	tests := []struct {
		input             *authnz.TargetMsg
		action            *policy.Action
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 0 - No policies
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			action: &policy.Action{
				Type:       policy.OIDC,
				Client:     &fake.Client{},
				ClientName: "name",
			},
			endpoints:         []policy.Endpoint{},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 1 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			action: &policy.Action{
				Type:       policy.OIDC,
				Client:     &fake.Client{},
				ClientName: "name",
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.OIDC,
			expectedRuleCount: 1,
			err:               nil,
		},
	}

	for i, test := range tests {
		/// Create new engine
		store := store.New().(*store.LocalStore)
		store.AddClient("client", &fake.Client{Server: &fake.AuthServer{}})
		eng := &engine{store: store}
		for _, ep := range test.endpoints {
			log.Info(ep) //so it wont throw an error
			if test.action != nil {
				store.SetWebPolicy(ep, *test.action)
			}

		}
		// Result
		result, err := eng.Evaluate(test.input)
		if test.err != nil {
			assert.Equal(t, test.err, err, "Expected to receive error : "+fmt.Sprintf("%v", i))
		} else {
			assert.Equal(t, test.expectedRuleCount, len(result.Rules), "Wrong number of policies returned for tests case : "+fmt.Sprintf("%v", i))
			assert.Equal(t, test.expectedAction, result.Type, "Unexpected action type returned for tests case : "+fmt.Sprintf("%v", i))
		}
	}
}

func TestEvaluateJWTAndOIDCPolicies(t *testing.T) {
	tests := []struct {
		input             *authnz.TargetMsg
		action            *policy.Action
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 1 - 1 policy
			input: generateActionMessage("namespace", "svc", "/path", "POST"),
			action: &policy.Action{
				Type:       policy.OIDC,
				Client:     &fake.Client{},
				ClientName: "name",
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               errors.New("conflicting OIDC and JWT policies"),
		},
	}

	for i, test := range tests {
		/// Create new engine
		store := store.New().(*store.LocalStore)
		store.AddAuthServer("serverurl", &fake.AuthServer{})
		store.AddClient("client", &fake.Client{Server: store.GetAuthServer("serverurl")})
		eng := &engine{store: store}
		for _, ep := range test.endpoints {
			log.Info(ep) //so it wont throw an error
			// TODO:
			store.SetApiPolicy(ep, *test.action)
			store.SetWebPolicy(ep, *test.action)
		}
		// Result
		result, err := eng.Evaluate(test.input)
		if test.err != nil {
			assert.Equal(t, test.err.Error(), err.Error(), "Expected to receive error : "+fmt.Sprintf("%v", i))
		} else {
			assert.Equal(t, test.expectedRuleCount, len(result.Rules), "Wrong number of policies returned for tests case : "+fmt.Sprintf("%v", i))
			assert.Equal(t, test.expectedAction, result.Type, "Unexpected action type returned for tests case : "+fmt.Sprintf("%v", i))
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

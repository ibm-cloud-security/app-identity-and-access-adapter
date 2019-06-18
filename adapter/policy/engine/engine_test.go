package engine

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
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
		pathPolicy        []v1.PathPolicy
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 0 - no policies
			input:             genActionMessage("", "", "", ""),
			pathPolicy:        nil,
			endpoints:         []policy.Endpoint{},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 1 - 1 policy
			input:      genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 2 - logout
			input:      genActionMessage("namespace", "svc", "/path/oidc/logout", "POST"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 3 - callback
			input:      genActionMessage("namespace", "svc", "/path/oidc/callback", "POST"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 4 - Diff method
			input:      genActionMessage("namespace", "svc", "/path", "GET"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 5 - Diff service
			input:      genActionMessage("namespace", "svc", "/path", "GET"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc2", "/path", "GET"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 6 - Diff namespace
			input:      genActionMessage("namespace", "svc", "/path", "GET"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace2", "svc", "/path", "GET"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 7 - Diff Path
			input:      genActionMessage("namespace", "svc", "/path", "GET"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/hello", "GET"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 8 - Generic Path
			input:      genActionMessage("namespace", "svc", "/path", "GET"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/*", "ALL"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 9 - Generic Method
			input:      genActionMessage("namespace", "svc", "/path", "OTHER"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "ALL"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 10 - Generic Path / Method
			input:      genActionMessage("namespace", "svc", "/path", "GET"),
			pathPolicy: genJWTPathPolicyArray(defaultJwtConfigName),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/*", "ALL"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1,
			err:               nil,
		},
		{
			// 11 - missing KeySet
			input:      genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: genJWTPathPolicyArray(""),
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               errors.New("missing JWK Set : cannot authorize request"),
		},
		{
			// 12 - existing rules
			input: genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: []v1.PathPolicy{
				{
					PolicyType: "jwt",
					Config:     defaultJwtConfigName,
					/*Rules: []policy.Rule{
						{
							Key:   "key",
							Value: "expected_value",
						},
					},*/
				},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.JWT,
			expectedRuleCount: 1, //2, revert when rules exist
			err:               nil,
		},
	}

	for _, ts := range tests {
		/// Create new engine
		test := ts
		t.Run("Engine", func(t *testing.T) {
			t.Parallel()
			store := policy2.New().(*policy2.LocalStore)
			store.AddKeySet("namespace.default-jwt-config", &fake.KeySet{})
			eng := &engine{store: store}

			if test.pathPolicy != nil {
				for _, ep := range test.endpoints {
					store.SetPolicies(ep, test.pathPolicy)
				}
			}

			result, err := eng.Evaluate(test.input)

			// Result
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else if err != nil {
				t.Fail()
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
		pathPolicy        []v1.PathPolicy
		endpoints         []policy.Endpoint
		expectedAction    policy.Type
		expectedRuleCount int
		err               error
	}{
		{
			// 0 - No policies
			input: genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: []v1.PathPolicy{
				{
					PolicyType: "oidc",
					Config:     defaultOidcConfigName,
				},
			},
			endpoints:         []policy.Endpoint{},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               nil,
		},
		{
			// 1 - 1 policy
			input: genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: []v1.PathPolicy{
				{
					PolicyType: "oidc",
					Config:     defaultOidcConfigName,
				},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.OIDC,
			expectedRuleCount: 1,
			err:               nil,
		},
		/*{ Uncomment when rules exist
			// 2 - existing rules
			input: genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: []v1.PathPolicy{
				{
					PolicyType: "oidc",
					Config:     defaultOidcConfigName,
					Rules: []policy.Rule{
						{
							Key:   "key",
							Value: "expected_value",
						},
					},
				},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.OIDC,
			expectedRuleCount: 2,
			err:               nil,
		},*/
		{
			// 3 - missing client
			input: genActionMessage("namespace", "svc", "/path", "POST"),
			pathPolicy: []v1.PathPolicy{
				{
					PolicyType: "oidc",
					Config:     "other client",
				},
			},
			endpoints: []policy.Endpoint{
				genEndpoint("namespace", "svc", "/path", "POST"),
			},
			expectedAction:    policy.NONE,
			expectedRuleCount: 0,
			err:               errors.New("missing OIDC client : cannot authenticate user"),
		},
	}

	for _, ts := range tests {
		test := ts
		t.Run("OIDCTests", func(t *testing.T) {
			t.Parallel()
			/// Create new engine
			store := policy2.New().(*policy2.LocalStore)
			store.AddClient("namespace."+defaultOidcConfigName, fake.NewClient(nil))
			eng := &engine{store: store}
			if test.pathPolicy != nil {
				for _, ep := range test.endpoints {
					store.SetPolicies(ep, test.pathPolicy)
				}
			}
			// Result
			result, err := eng.Evaluate(test.input)
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else if err != nil {
				t.Fail()
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

func genActionMessage(ns string, svc string, path string, method string) *authnz.TargetMsg {
	return &authnz.TargetMsg{
		Namespace: ns,
		Service:   svc,
		Path:      path,
		Method:    method,
	}
}

const defaultOidcConfigName = "default-oidc-config"
const defaultJwtConfigName = "default-jwt-config"

func genJWTPathPolicyArray(cfg string) []v1.PathPolicy {
	return []v1.PathPolicy{
		{
			PolicyType: "jwt",
			Config:     cfg,
		},
	}
}

// Package engine is responsible for making policy decisions
package engine

import (
	"errors"
	"strings"

	"go.uber.org/zap"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	policy2 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
)

const (
	aud              = "aud"
	iss              = "iss"
	logoutEndpoint   = "/oidc/logout"
	callbackEndpoint = "/oidc/callback"
)

// PolicyEngine is responsible for making policy decisions
type PolicyEngine interface {
	Evaluate(msg *authnz.TargetMsg) (*policy.Action, error)
}

type engine struct {
	store policy2.PolicyStore
}

// New creates a PolicyEngine
func New(store policy2.PolicyStore) (PolicyEngine, error) {
	if store == nil {
		zap.L().Error("Trying to create PolicyEngine, but no store provided.")
		return nil, errors.New("could not create policy engine using undefined store")
	}
	return &engine{store: store}, nil
}

////////////////// interface //////////////////

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *engine) Evaluate(target *authnz.TargetMsg) (*policy.Action, error) {
	zap.L().Debug("Evaluating policies",
		zap.String("namespace", target.Namespace),
		zap.String("service", target.Service),
		zap.String("path", target.Path),
		zap.String("method", target.Method),
	)

	if strings.HasSuffix(target.Path, callbackEndpoint) {
		target.Path = strings.Split(target.Path, callbackEndpoint)[0]
	} else if strings.HasSuffix(target.Path, logoutEndpoint) {
		target.Path = strings.Split(target.Path, logoutEndpoint)[0]
	}

	policies := m.getPolicies(endpointsToCheck(target))

	zap.L().Debug("Checking policies", zap.Int("count", len(policies)))
	if len(policies) == 0 {
		return &policy.Action{
			Type: policy.NONE,
		}, nil
	}

	for i, p := range policies {
		if p.Type == policy.JWT && p.KeySet == nil {
			zap.L().Error("Missing JWKS set : cannot authenticate user")
			return nil, errors.New("missing JWKs set : cannot authenticate user")
		} else if p.Type == policy.OIDC && p.Client == nil {
			zap.L().Error("Missing OIDC client : cannot authenticate user")
			return nil, errors.New("missing OIDC client : cannot authenticate user")
		}

		if p.Rules == nil {
			policies[i].Rules = createDefaultRules(p)
		} else {
			policies[i].Rules = append(p.Rules, createDefaultRules(p)...)
		}
	}

	// Temporarily return only 1 policy. When we support multiple and decide on behavior this can be updated.
	return &policies[0], nil
}

////////////////// utils //////////////////

// getPolicies returns policies for the given endpoints
func (m *engine) getPolicies(endpoints []policy.Endpoint) []policy.Action {
	size := 0
	tmp := make([]policy.Action, size)

	for _, ep := range endpoints {
		if action := m.store.GetPolicies(ep); action != nil {
			tmp = append(tmp, action...)
		}
	}

	return tmp
}

// createDefaultRules generates the default JWT validation rules for the given client
func createDefaultRules(action policy.Action) []policy.Rule {
	switch action.Type {
	case policy.JWT:
		return []policy.Rule{
			{
				Key:   iss,
				Value: action.KeySet.PublicKeyURL(),
			},
		}
	case policy.OIDC:
		return []policy.Rule{
			{
				Key:   aud,
				Value: action.Client.ID(),
			},
		}
	default:
		return []policy.Rule{}
	}
}

func endpointsToCheck(target *authnz.TargetMsg) []policy.Endpoint {
	service := policy.Service{Namespace: target.Namespace, Name: target.Service}
	return []policy.Endpoint{
		{Service: service, Path: target.Path, Method: policy.NewMethod(target.Method)},
		{Service: service, Path: target.Path, Method: policy.ALL},
		{Service: service, Path: "/*", Method: policy.ALL},
	}
}

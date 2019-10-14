// Package engine is responsible for making policy decisions
package engine

import (
	"errors"
	"strings"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"

	"go.uber.org/zap"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
	policy2 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy/store/policy"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/config/template"
)

const (
	aud              = "aud"
	iss              = "iss"
	logoutEndpoint   = "/oidc/logout"
	callbackEndpoint = "/oidc/callback"
)

// PolicyEngine is responsible for making policy decisions
type PolicyEngine interface {
	Evaluate(msg *authnz.TargetMsg) (*Action, error)
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

// //////////////// interface //////////////////

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *engine) Evaluate(target *authnz.TargetMsg) (*Action, error) {
	zap.L().Debug("Evaluating policies",
		zap.String("namespace", target.Namespace),
		zap.String("service", target.Service),
		zap.String("path", target.Path),
		zap.String("method", target.Method),
	)

	// Strip custom path components
	if strings.HasSuffix(target.Path, callbackEndpoint) {
		target.Path = strings.Split(target.Path, callbackEndpoint)[0]
	} else if strings.HasSuffix(target.Path, logoutEndpoint) {
		target.Path = strings.Split(target.Path, logoutEndpoint)[0]
	}

	// Get All policies protecting target
	policies, err := m.getPolicies(endpointsToCheck(target))
	if err != nil {
		zap.L().Error("Could not retrieve configured policies", zap.Error(err))
		return nil, err
	}

	zap.L().Debug("Checking policies", zap.Int("count", len(policies)))
	if len(policies) == 0 {
		return &Action{
			Type: policy.NONE,
		}, nil
	}

	// Validate and cleanse action policies
	for i, p := range policies {
		if p.Rules == nil {
			policies[i].Rules = createDefaultRules(p)
		} else {
			policies[i].Rules = append(p.Rules, createDefaultRules(p)...)
		}
	}

	// Temporarily return only 1 policy. When we support multiple and decide on behavior this can be updated.
	return &policies[0], nil
}

// //////////////// utils //////////////////

// getPolicies returns policies for the given endpoints
func (m *engine) getPolicies(endpoints []policy.Endpoint) ([]Action, error) {
	actions := make([]Action, 0)
	// Check all possible endpoint variants for policies
	// retrieve policies configured for the endpoint
	for _, ep := range endpoints {
		endpointActions, err := m.parseActions(ep, m.store.GetPolicies(ep), "policy")
		if err != nil {
			return nil, err
		}
		if len(endpointActions) > 0 {
			actions = append(actions, endpointActions...)
		}
	}
	// retrieve prefix policies configured for the endpoint
	for _, ep := range endpoints {
		endpointActions, err := m.parseActions(ep, m.store.GetPrefixPolicies(ep), "prefix policies")
		if err != nil {
			return nil, err
		}
		if len(endpointActions) > 0 {
			actions = append(actions, endpointActions...)
		}
	}
	return actions, nil
}

func (m *engine) parseActions(endpoint policy.Endpoint, routePolicy policy.RoutePolicy, message string) ([]Action, error) {
	zap.L().Debug("Retrieving "+message+" for endpoint",
		zap.String("namespace", endpoint.Service.Namespace),
		zap.String("service", endpoint.Service.Name),
		zap.String("path", endpoint.Path),
		zap.String("method", endpoint.Method.String()))
	if len(routePolicy.Actions) > 0 {
		// Convert policy definition into Action
		endpointActions := make([]Action, len(routePolicy.Actions))
		for i, p := range routePolicy.Actions {
			action := Action{
				PathPolicy: p,
				Type:       policy.NewType(p.PolicyType),
			}

			configName := endpoint.Service.Namespace + "/" + p.Config
			zap.L().Debug("Checking for configuration", zap.String("name", configName), zap.String("type", action.PolicyType))

			switch action.Type {
			case policy.JWT:
				if set := m.store.GetKeySet(configName); set != nil {
					action.KeySet = set
				} else {
					return nil, errors.New("missing JWK Set : cannot authorize request")
				}
			case policy.OIDC:
				if client := m.store.GetClient(configName); client != nil {
					action.Client = client
				} else {
					return nil, errors.New("missing OIDC client : cannot authenticate user")
				}
			default:
				return nil, errors.New("unexpected policy configuration")
			}
			endpointActions[i] = action
		}

		return endpointActions, nil
	} else {
		zap.L().Debug("No "+message+" for endpoint",
			zap.String("namespace", endpoint.Service.Namespace),
			zap.String("service", endpoint.Service.Name),
			zap.String("path", endpoint.Path),
			zap.String("method", endpoint.Method.String()))
	}
	return make([]Action, 0), nil
}

// createDefaultRules generates the default JWT validation rules for the given client
func createDefaultRules(action Action) []v1.Rule {
	switch action.Type {
	case policy.OIDC:
		return []v1.Rule{
			{
				Claim:  aud,
				Match:  "ANY",
				Values: []string{action.Client.ID()},
			},
		}
	default:
		return []v1.Rule{}
	}
}

// endpointsToCheck returns the possible endpoints housing the authn/z policies for the given target
func endpointsToCheck(target *authnz.TargetMsg) []policy.Endpoint {
	service := policy.Service{Namespace: target.Namespace, Name: target.Service}
	method := policy.NewMethod(target.Method)
	endpoints := []policy.Endpoint{{Service: service, Path: target.Path, Method: method}}
	if method != policy.ALL {
		endpoints = append(endpoints, policy.Endpoint{Service: service, Path: target.Path, Method: policy.ALL})
	}
	return endpoints
}

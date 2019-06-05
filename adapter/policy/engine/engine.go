// Package engine is responsible for making policy decisions
package engine

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"go.uber.org/zap"
	"strings"
)

const (
	logoutEndpoint   = "/oidc/logout"
	callbackEndpoint = "/oidc/callback"
)

// PolicyEngine is responsible for making policy decisions
type PolicyEngine interface {
	Evaluate(msg *authnz.TargetMsg) (*policy.Action, error)
}

type engine struct {
	store store.PolicyStore
}

// New creates a PolicyEngine
func New(store store.PolicyStore) (PolicyEngine, error) {
	if store == nil {
		zap.L().Error("Trying to create PolicyEngine, but no store provided.")
		return nil, errors.New("could not create policy engine using undefined store")
	}
	return &engine{store: store}, nil
}

////////////////// interface //////////////////

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *engine) Evaluate(action *authnz.TargetMsg) (*policy.Action, error) {
	zap.L().Debug("Evaluating policies",
		zap.String("namespace", action.Namespace),
		zap.String("service", action.Service),
		zap.String("path", action.Path),
		zap.String("method", action.Method),
	)

	if strings.HasSuffix(action.Path, callbackEndpoint) {
		action.Path = strings.Split(action.Path, callbackEndpoint)[0]
	} else if strings.HasSuffix(action.Path, logoutEndpoint) {
		action.Path = strings.Split(action.Path, logoutEndpoint)[0]
	}

	endpoints := endpointsToCheck(action.Namespace, action.Service, action.Path, action.Method)
	jwtPolicies := m.getJWTPolicies(endpoints)
	oidcPolicies := m.getOIDCPolicies(endpoints)
	zap.L().Debug("Checking policies", zap.Int("jwt-policy-count", len(jwtPolicies)), zap.Int("oidc-policy-count", len(oidcPolicies)))
	if len(oidcPolicies) == 0 && len(jwtPolicies) == 0 {
		return &policy.Action{
			Type: policy.NONE,
		}, nil
	}

	if len(oidcPolicies) > 0 && len(jwtPolicies) > 0 {
		zap.L().Warn("Found conflicting OIDC and JWT policies. Rejecting Request. Please check your policy configuration.")
		return nil, errors.New("conflicting OIDC and JWT policies")
	}

	if len(oidcPolicies) > 0 {
		return m.createOIDCAction(oidcPolicies)
	}

	return m.createJWTAction(jwtPolicies)
}

////////////////// instance utils //////////////////

// getJWTPolicies returns JWT for the given endpoints
func (m *engine) getJWTPolicies(endpoints []policy.Endpoint) []policy.Action {
	size := 0
	tmp := make([]policy.Action, size)

	for _, ep := range endpoints {
		if action := m.store.GetApiPolicies(ep); action != nil {
			tmp = append(tmp, *action)
		}
	}

	return tmp
}

// getOIDCPolicies returns OIDC for the given endpoints
func (m *engine) getOIDCPolicies(endpoints []policy.Endpoint) []policy.Action {
	size := 0
	tmp := make([]policy.Action, size)

	for _, e := range endpoints {
		if action := m.store.GetWebPolicies(e); action != nil {
			tmp = append(tmp, *action)
		}
	}
	return tmp
}

// createJWTAction creates api strategy actions
func (m *engine) createJWTAction(policies []policy.Action) (*policy.Action, error) {
	if len(policies) == 0 {
		return &policy.Action{Type: policy.NONE}, nil
	}
	return &policies[0], nil
}

// createOIDCAction creates web strategy actions
func (m *engine) createOIDCAction(policies []policy.Action) (*policy.Action, error) {
	if len(policies) == 0 {
		return &policy.Action{Type: policy.NONE}, nil
	}

	p := &policies[0]
	if p.Client == nil {
		if c := m.store.GetClient(p.ClientName); c != nil {
			p.Client = c
		} else {
			zap.L().Error("Missing OIDC client : cannot authenticate user")
			return nil, errors.New("missing OIDC client : cannot authenticate user")
		}
	}

	p.Rules = []policy.Rule{{
		Key:   "aud",
		Value: p.Client.ID(),
	}}

	return p, nil
}

////////////////// utils //////////////////

func endpointsToCheck(namespace string, svc string, path string, method string) []policy.Endpoint {
	return []policy.Endpoint{
		{Namespace: namespace, Service: svc, Path: path, Method: method},
		{Namespace: namespace, Service: svc, Path: path, Method: "*"},
		{Namespace: namespace, Service: svc, Path: "*", Method: "*"},
	}
}

// Package engine is responsible for making policy decisions
package engine

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
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

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type   policy.Type
	KeySet keyset.KeySet
	Client client.Client
	Rules  []policy.Rule
}

// PolicyEngine is responsible for making policy decisions
type PolicyEngine interface {
	Evaluate(msg *authnz.TargetMsg) (*Action, error)
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
func (m *engine) Evaluate(action *authnz.TargetMsg) (*Action, error) {
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
	if (oidcPolicies == nil || len(oidcPolicies) == 0) && (jwtPolicies == nil || len(jwtPolicies) == 0) {
		return &Action{
			Type: policy.NONE,
		}, nil
	}

	if (oidcPolicies != nil && len(oidcPolicies) > 0) && (jwtPolicies != nil && len(jwtPolicies) > 0) {
		zap.L().Warn("Found conflicting OIDC and JWT policies. Rejecting Request. Please check your policy configuration.")
		return nil, errors.New("conflicting OIDC and JWT policies")
	}

	if oidcPolicies != nil && len(oidcPolicies) > 0 {
		return m.createOIDCAction(oidcPolicies)
	}

	return m.createJWTAction(jwtPolicies)
}

////////////////// instance utils //////////////////

// getJWTPolicies returns JWT for the given endpoints
func (m *engine) getJWTPolicies(endpoints []policy.Endpoint) []v1.JwtPolicySpec {
	size := 0
	for _, e := range endpoints {
		if list := m.store.GetApiPolicies(e); list != nil {
			size += len(list)
		}
	}
	tmp := make([]v1.JwtPolicySpec, size)
	var i int
	for _, e := range endpoints {
		list := m.store.GetApiPolicies(e)
		if list != nil && len(list) > 0 {
			i += copy(tmp[i:], list)
		}
	}
	return tmp
}

// getOIDCPolicies returns OIDC for the given endpoints
func (m *engine) getOIDCPolicies(endpoints []policy.Endpoint) []v1.OidcPolicySpec {
	size := 0
	for _, e := range endpoints {
		if list := m.store.GetWebPolicies(e); list != nil {
			size += len(list)
		}
	}
	tmp := make([]v1.OidcPolicySpec, size)
	var i int
	for _, e := range endpoints {
		list := m.store.GetWebPolicies(e)
		if list != nil && len(list) > 0 {
			i += copy(tmp[i:], list)
		}
	}
	return tmp
}

// createJWTAction creates api strategy actions
func (m *engine) createJWTAction(policies []v1.JwtPolicySpec) (*Action, error) {
	if len(policies) == 0 {
		return &Action{Type: policy.NONE}, nil
	}

	if keyset := m.store.GetKeySet(policies[0].JwksURL); keyset != nil {
		return &Action{
			Type:   policy.JWT,
			KeySet: keyset,
		}, nil
	}

	zap.L().Error("Missing authentication server : cannot authenticate user")
	return nil, errors.New("missing authentication server : cannot authenticate user")
}

// createOIDCAction creates web strategy actions
func (m *engine) createOIDCAction(policies []v1.OidcPolicySpec) (*Action, error) {
	if len(policies) == 0 {
		return &Action{Type: policy.NONE}, nil
	}

	if c := m.store.GetClient(policies[0].ClientName); c != nil {
		rules := []policy.Rule{{
			Key:   "aud",
			Value: c.ID(),
		}}
		return &Action{
			Type:   policy.OIDC,
			Client: c,
			Rules:  rules,
		}, nil

	}

	zap.L().Error("Missing OIDC client : cannot authenticate user")
	return nil, errors.New("missing OIDC client : cannot authenticate user")
}

////////////////// utils //////////////////

func endpointsToCheck(namespace string, svc string, path string, method string) []policy.Endpoint {
	return []policy.Endpoint{
		{Namespace: namespace, Service: svc, Path: path, Method: method},
		{Namespace: namespace, Service: svc, Path: path, Method: "*"},
		{Namespace: namespace, Service: svc, Path: "*", Method: "*"},
	}
}

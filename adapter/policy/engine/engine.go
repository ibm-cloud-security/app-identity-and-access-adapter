// Package engine is responsible for making policy decisions
package engine

import (
	//"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/authserver/keyset"
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/store"

	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type     policy.Type
	Policies []PolicyAction
}

// PolicyAction captures data necessary to process a particular policy
type PolicyAction struct {
	KeySet keyset.KeySet
	// Rule []Rule
}

// PolicyEngine is responsible for making policy decisions
type PolicyEngine interface {
	Evaluate(*authorization.ActionMsg) Action
}

type engine struct {
	store store.PolicyStore
}

// New creates a PolicyEngine
func New(store store.PolicyStore) PolicyEngine {
	return &engine{
		store: store,
	}
}

////////////////// interface //////////////////

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *engine) Evaluate(action *authorization.ActionMsg) Action {
	endpoints := endpointsToCheck(action.Namespace, action.Service, action.Path, action.Method)
	jwtPolicies := m.getJWTPolicies(endpoints)
	oidcPolicies := m.getOIDCPolicies(endpoints)
	log.Debugf("JWT policies: %v | OIDC policies: %v", len(jwtPolicies), len(oidcPolicies))
	if (oidcPolicies == nil || len(oidcPolicies) == 0) && (jwtPolicies == nil || len(jwtPolicies) == 0) {
		return Action{
			Type: policy.NONE,
		}
	}

	if (oidcPolicies != nil && len(oidcPolicies) > 0) && (jwtPolicies != nil && len(jwtPolicies) > 0) {
		// Make decision
		return Action{
			Type: policy.NONE,
		}
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
	/*
		size := 0
		for _, e := range endpoints {
			if list, ok := m.webPolicies[e]; ok {
				size += len(list)
			}
		}
		tmp := make([]v1.OidcPolicySpec, size)
		var i int
		for _, e := range endpoints {
			if list, ok := m.webPolicies[e]; ok && len(list) > 0 {
				i += copy(tmp[i:], list)
			}
		}
		return tmp
	*/
	return []v1.OidcPolicySpec{}
}

// createJWTAction creates api strategy actions
func (m *engine) createJWTAction(policies []v1.JwtPolicySpec) Action {
	actions := make([]PolicyAction, 0)
	for i := 0; i < len(policies); i++ {
		actions = append(actions, PolicyAction{
			KeySet: m.store.GetAuthServer(policies[i].JwksURL).KeySet(),
		})
	}

	return Action{
		Type:     policy.JWT,
		Policies: actions,
	}
}

// createOIDCAction creates web strategy actions
func (m *engine) createOIDCAction(policies []v1.OidcPolicySpec) Action {
	actions := make([]PolicyAction, len(policies))
	for i := 0; i < len(policies); i++ {
		actions = append(actions, PolicyAction{
			KeySet: m.store.GetClient(policies[i].ClientName).AuthServer.KeySet(),
		})
	}
	return Action{
		Type:     policy.OIDC,
		Policies: actions,
	}
}

////////////////// utils //////////////////

func endpointsToCheck(namespace string, svc string, path string, method string) []policy.Endpoint {
	return []policy.Endpoint{
		policy.Endpoint{Namespace: namespace, Service: svc, Path: path, Method: method},
		policy.Endpoint{Namespace: namespace, Service: svc, Path: path, Method: "*"},
		policy.Endpoint{Namespace: namespace, Service: svc, Path: "*", Method: "*"},
	}
}

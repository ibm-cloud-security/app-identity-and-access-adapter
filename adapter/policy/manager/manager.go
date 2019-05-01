// Package manager is responsible for monitoring and maintaining authn/z policies
package manager

import (
	"reflect"
	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/authserver/keyset"
	"ibmcloudappid/adapter/client"
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"

	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

// PolicyManager is responsible for storing and managing policy/client data
type PolicyManager interface {
	Evaluate(*authorization.ActionMsg) Action
	HandleAddEvent(obj interface{})
	HandleDeleteEvent(obj interface{})
}

// Manager is responsible for storing and managing policy/client data
type Manager struct {
	// clients maps client_name -> client_config
	clients map[string]*client.Client
	// authserver maps jwksurl -> AuthorizationServers
	authservers map[string]authserver.AuthorizationServer
	// policies maps endpoint -> list of policies
	apiPolicies map[endpoint][]v1.JwtPolicySpec
	// policies maps endpoint -> list of policies
	webPolicies map[endpoint][]v1.OidcPolicySpec
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string]PolicyMapping
}

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

type endpoint struct {
	namespace, service, path, method string
}

// PolicyMapping captures information of created endpoints by policy
type PolicyMapping struct {
	Type     	policy.Type
	Endpoints 	[]endpoint
	Spec 		interface{}
}

////////////////// constructor //////////////////
//map[int]bool
// New creates a PolicyManager
func New() PolicyManager {
	return &Manager{
		clients:     make(map[string]*client.Client),
		authservers: make(map[string]authserver.AuthorizationServer),
		apiPolicies: make(map[endpoint][]v1.JwtPolicySpec),
		webPolicies: make(map[endpoint][]v1.OidcPolicySpec),
		policyMappings: make(map[string]PolicyMapping),
	}
}

////////////////// interface //////////////////

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *Manager) Evaluate(action *authorization.ActionMsg) Action {
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

// HandleAddEvent updates the store after a CRD has been added
func (m *Manager) HandleAddEvent(obj interface{}) {
	switch crd := obj.(type) {
	case *v1.JwtPolicy:
		log.Debugf("Created JwtPolicy : ID: %s", crd.ObjectMeta.UID)

		// If we already are tracking this authentication server, skip
		if _, ok := m.authservers[crd.Spec.JwksURL]; !ok {
			m.authservers[crd.Spec.JwksURL] = authserver.New(crd.Spec.JwksURL)
		}
		mappingKey := crd.ObjectMeta.Namespace + "/" + crd.ObjectMeta.Name
		// Process target endpoints
		policyEndpoints := parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace)
		if _, ok := m.policyMappings[mappingKey]; ok {
			// for update delete the old object mappings
			log.Debugf("Update event for Policy. Calling Delete to remove the old mappings")
			m.HandleDeleteEvent(policy.CrdKey{Id : mappingKey})
		}
		m.policyMappings[mappingKey] = PolicyMapping{Type: policy.JWT, Endpoints: policyEndpoints, Spec: crd.Spec}
		for _, ep := range policyEndpoints {
			if m.apiPolicies == nil {
				m.apiPolicies[ep] = make([]v1.JwtPolicySpec, 0)
			}
			m.apiPolicies[ep] = append(m.apiPolicies[ep], crd.Spec)
		}
		log.Infof("JwtPolicy created : ID %s", crd.ObjectMeta.UID)
	case *v1.OidcPolicy:
		log.Debugf("OidcPolicy created : ID: %s", crd.ObjectMeta.UID)
		log.Infof("OidcPolicy created : ID %s", crd.ObjectMeta.UID)
	case *v1.OidcClient:
		log.Debugf("Creating OidcClient : ID: %s", crd.ObjectMeta.UID)
		log.Infof("OidcClient created : ID %s", crd.ObjectMeta.UID)
	default:
		log.Errorf("Could not create object. Unknown type : %f", crd)
	}
}

// HandleDeleteEvent updates the store after a CRD has been deleted
func (m *Manager) HandleDeleteEvent(obj interface{}) {
	mappingId := obj.(policy.CrdKey)
	mapping := m.policyMappings[mappingId.Id]
	switch mapping.Type {
	case policy.JWT:
		log.Debugf("Deleting Object of type : %f", policy.JWT)
		for _, ep := range mapping.Endpoints {
			loc := -1
			for index , value := range m.apiPolicies[ep] {
				if reflect.DeepEqual(value, mapping.Spec) {
					loc = index
					break
				}
			}
			if loc >= 0 {
				copy(m.apiPolicies[ep][loc:],  m.apiPolicies[ep][loc+1:])
				m.apiPolicies[ep] = m.apiPolicies[ep][:len(m.apiPolicies[ep])-1]
			}
		}
		delete(m.policyMappings, mappingId.Id)
		log.Debug("Delete Complete")
	case policy.OIDC:
		log.Debugf("Deleting Object of type : %f", policy.OIDC)
		for _, ep := range mapping.Endpoints {
			loc := -1
			for index , value := range m.webPolicies[ep] {
				if reflect.DeepEqual(value, mapping.Spec) {
					loc = index
					break
				}
			}
			if loc >= 0 {
				copy(m.webPolicies[ep][loc:],  m.webPolicies[ep][loc+1:])
				m.webPolicies[ep] = m.webPolicies[ep][:len(m.webPolicies[ep])-1]
			}
		}
		log.Debug("Delete Complete")

	default:
		log.Errorf("Could not delete object. Unknown type : %f", mapping.Type)
	}
}

////////////////// instance utils //////////////////

// getJWTPolicies returns JWT for the given endpoints
func (m *Manager) getJWTPolicies(endpoints []endpoint) []v1.JwtPolicySpec {
	size := 0
	for _, e := range endpoints {
		if list, ok := m.apiPolicies[e]; ok {
			size += len(list)
		}
	}
	tmp := make([]v1.JwtPolicySpec, size)
	var i int
	for _, e := range endpoints {
		if list, ok := m.apiPolicies[e]; ok && len(list) > 0 {
			i += copy(tmp[i:], list)
		}
	}
	return tmp
}

// getOIDCPolicies returns OIDC for the given endpoints
func (m *Manager) getOIDCPolicies(endpoints []endpoint) []v1.OidcPolicySpec {
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
}

// createJWTAction creates api strategy actions
func (m *Manager) createJWTAction(policies []v1.JwtPolicySpec) Action {
	actions := make([]PolicyAction, 0)
	for i := 0; i < len(policies); i++ {
		actions = append(actions, PolicyAction{
			KeySet: m.authServer(policies[i].JwksURL).KeySet(),
		})
	}

	return Action{
		Type:     policy.JWT,
		Policies: actions,
	}
}

// createOIDCAction creates web strategy actions
func (m *Manager) createOIDCAction(policies []v1.OidcPolicySpec) Action {
	actions := make([]PolicyAction, len(policies))
	for i := 0; i < len(policies); i++ {
		actions = append(actions, PolicyAction{
			KeySet: m.client(policies[i].ClientName).AuthServer.KeySet(),
		})
	}
	return Action{
		Type:     policy.OIDC,
		Policies: actions,
	}
}

// Client returns the client instance given its name
func (m *Manager) client(clientName string) *client.Client {
	return m.clients[clientName]
}

// AuthServer returns the client instance given its name
func (m *Manager) authServer(jwksurl string) authserver.AuthorizationServer {
	return m.authservers[jwksurl]
}

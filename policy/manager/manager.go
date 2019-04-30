// Package manager is responsible for monitoring and maintaining authn/z policies
package manager

import (
	"reflect"
	"strings"

	"ibmcloudappid/authserver"
	"ibmcloudappid/authserver/keyset"
	"ibmcloudappid/client"
	"ibmcloudappid/policy"
	"istio.io/istio/mixer/template/authorization"

	v1 "ibmcloudappid/pkg/apis/policies/v1"
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

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *Manager) Evaluate(action *authorization.ActionMsg) Action {
	// Get destination service
	destinationService := strings.TrimSuffix(action.Service, "."+action.Namespace+".svc.cluster.local")

	ep := endpoint{
		namespace: action.Namespace,
		service:   destinationService,
		path:      "*",
		method:    "*",
	}
	log.Infof("Checking for policies on endpoint : %v", ep)
	apiPolicies := m.apiPolicies[ep]
	webPolicies := m.webPolicies[ep]
	if (webPolicies == nil || len(webPolicies) == 0) && (apiPolicies == nil || len(apiPolicies) == 0) {
		return Action{
			Type: policy.NONE,
		}
	}

	if (webPolicies != nil && len(webPolicies) >= 0) && (apiPolicies != nil && len(apiPolicies) > 0) {
		// Make decision
		return Action{
			Type: policy.NONE,
		}
	}

	if webPolicies != nil && len(webPolicies) >= 0 {
		return m.GetWebStrategyAction(webPolicies)
	}

	return m.GetAPIStrategyAction(apiPolicies)
}

// GetAPIStrategyAction creates api strategy actions
func (m *Manager) GetAPIStrategyAction(policies []v1.JwtPolicySpec) Action {
	actions := make([]PolicyAction, 0)
	for i := 0; i < len(policies); i++ {
		actions = append(actions, PolicyAction{
			KeySet: m.AuthServer(policies[i].JwksURL).KeySet(),
		})
	}
	log.Debugf("ACTIONS 2: %v", actions)

	return Action{
		Type:     policy.JWT,
		Policies: actions,
	}
}

// GetWebStrategyAction creates web strategy actions
func (m *Manager) GetWebStrategyAction(policies []v1.OidcPolicySpec) Action {
	actions := make([]PolicyAction, len(policies))
	for i := 0; i < len(policies); i++ {
		actions = append(actions, PolicyAction{
			KeySet: m.Client(policies[i].ClientName).AuthServer.KeySet(),
		})
	}
	return Action{
		Type:     policy.OIDC,
		Policies: actions,
	}
}

// Client returns the client instance given its name
func (m *Manager) Client(clientName string) *client.Client {
	return m.clients[clientName]
}

// AuthServer returns the client instance given its name
func (m *Manager) AuthServer(jwksurl string) authserver.AuthorizationServer {
	return m.authservers[jwksurl]
}

// New creates a PolicyManager
func New() PolicyManager {
	return &Manager{
		clients:     make(map[string]*client.Client),
		authservers: make(map[string]authserver.AuthorizationServer),
		apiPolicies: make(map[endpoint][]v1.JwtPolicySpec),
		webPolicies: make(map[endpoint][]v1.OidcPolicySpec),
	}
}

func (m *Manager) HandleAddEvent(obj interface{}) {
	switch crd := obj.(type) {
	case *v1.JwtPolicy:
		log.Debugf("TestHandler.ObjectCreated : *v1.JwtPolicy : ID: %s", crd.ObjectMeta.UID)

		// If we already are tracking this authentication server, skip
		if _, ok := m.authservers[crd.Spec.JwksURL]; !ok {
			m.authservers[crd.Spec.JwksURL] = authserver.New(crd.Spec.JwksURL)
		}

		// Process target endpoints
		for _, ep := range parseTarget(crd.Spec.Target, crd.ObjectMeta.Namespace) {
			if m.apiPolicies == nil {
				m.apiPolicies[ep] = make([]v1.JwtPolicySpec, 0)
			}
			m.apiPolicies[ep] = append(m.apiPolicies[ep], crd.Spec)
		}

		log.Infof("JwtPolicy Succesfully Created : ID %s", crd.ObjectMeta.UID)
	case *v1.OidcPolicy:
		log.Debug("TestHandler.ObjectCreated : *v1.OidcPolicy")
		log.Debugf("%v", crd)
		log.Debug("TestHandler.ObjectCreated OidcPolicy done---------")
	case *v1.OidcClient:
		log.Debug("TestHandler.ObjectCreated : *v1.OidcClient")
		log.Debugf("%v", crd)
		log.Debug("TestHandler.ObjectCreated OidcClient done---------")
	default:
		log.Error("Unknown Object")
	}
}

func (m *Manager) HandleDeleteEvent(obj interface{}) {
	switch crd := obj.(type) {
	case *v1.JwtPolicy:
		log.Infof("TestHandler.HandleDeleteEvent : *v1.JwkPolicy : ID: %s", crd.ObjectMeta.UID)
		namespace := crd.ObjectMeta.Namespace
		endpoints := parseTarget(crd.Spec.Target, namespace)
		for _, ep := range endpoints {
			if m.apiPolicies != nil || len(m.apiPolicies) > 0 {
				delete(m.apiPolicies, ep)
			}
		}
		log.Debug("HandleDeleteEvent : *v1.JwkPolicy done")
	case *v1.OidcPolicy:
		log.Debug("HandleDeleteEvent : *v1.OidcPolicy")
	case *v1.OidcClient:
		log.Debug("HandleDeleteEvent : *v1.OidcClient")
	default:
		log.Errorf("Unknown Object : %r", reflect.TypeOf(crd))
	}
}

func parseTarget(target []v1.TargetElement, namespace string) []endpoint {
	log.Infof("%v", target)
	endpoints := make([]endpoint, 0)
	if target != nil || len(target) != 0 {
		for _, items := range target {
			service := items.ServiceName
			if items.Paths != nil || len(items.Paths) != 0 {
				for _, path := range items.Paths {
					endpoints = append(endpoints, endpoint{namespace: namespace, service: service, path: path, method: "*"})
				}
			} else {
				endpoints = append(endpoints, endpoint{namespace: namespace, service: service, path: "*", method: "*"})
			}
		}
	}
	return endpoints
}

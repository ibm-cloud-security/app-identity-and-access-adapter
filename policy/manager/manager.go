// Package manager is responsible for monitoring and maintaining authn/z policies
package manager

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/authserver/keyset"
	"strings"

	c "istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/mixer/adapter/ibmcloudappid/authserver"
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy"
	"istio.io/istio/mixer/template/authorization"

	v1 "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/apis/policies/v1"
	"istio.io/istio/pkg/log"
)

// PolicyManager is responsible for storing and managing policy/client data
type PolicyManager interface {
	Evaluate(*authorization.ActionMsg) Action
	HandleEvent(obj interface{})
}

// Manager is responsible for storing and managing policy/client data
type Manager struct {
	// clients maps client_name -> client_config
	clients map[string]*c.Client
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
	policies []PolicyAction
}

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
		path:      action.Path,
		method:    action.Method,
	}

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
		// Make decision
		return m.GetWebStrategyAction(webPolicies)
	}

	return m.GetAPIStrategyAction(apiPolicies)
}

func (m *Manager) GetAPIStrategyAction(policies []v1.JwtPolicySpec) Action {
	return Action{
		Type: policy.API,
		policies: []PolicyAction{
			PolicyAction{
				KeySet: m.AuthServer(policies[0].JwksURL).KeySet(),
			},
		},
	}
}

func (m *Manager) GetWebStrategyAction(policies []v1.OidcPolicySpec) Action {
	return Action{
		Type: policy.WEB,
		policies: []PolicyAction{
			PolicyAction{
				KeySet: m.Client(policies[0].ClientName).AuthServer.KeySet(),
			},
		},
	}
}

// Client returns the client instance given its name
func (m *Manager) Client(clientName string) *c.Client {
	return m.clients[clientName]
}

// AuthServer returns the client instance given its name
func (m *Manager) AuthServer(jwksurl string) authserver.AuthorizationServer {
	return m.authservers[jwksurl]
}

// New creates a PolicyManager
func New() PolicyManager {
	return &Manager{
		clients:     make(map[string]*c.Client),
		authservers: make(map[string]authserver.AuthorizationServer),
		apiPolicies: make(map[endpoint][]v1.JwtPolicySpec),
		webPolicies: make(map[endpoint][]v1.OidcPolicySpec),
	}
}

func (m *Manager) HandleEvent(obj interface{}) {
	switch obj.(type){
	case *v1.JwtPolicy:
		log.Debug("TestHandler.ObjectCreated : *v1.JwkPolicy")
		jwk := obj.(*v1.JwtPolicy)
		log.Debugf("%r", jwk)
		log.Debug("TestHandler.ObjectCreated JwkPolicy done---------")
	case *v1.OidcPolicy:
		log.Debug("TestHandler.ObjectCreated : *v1.OidcPolicy")
		oidc := obj.(*v1.OidcPolicy)
		log.Debugf("%r", oidc)
		log.Debug("TestHandler.ObjectCreated OidcPolicy done---------")
	case *v1.OidcClient:
		log.Debug("TestHandler.ObjectCreated : *v1.OidcClient")
		client := obj.(*v1.OidcClient)
		log.Debugf("%r", client)
		log.Debug("TestHandler.ObjectCreated OidcClient done---------")
	default :
		log.Error("Unknown Object")
	}
}
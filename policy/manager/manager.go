// Package manager is responsible for monitoring and maintaining authn/z policies
package manager

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy"
	"istio.io/istio/mixer/template/authorization"
	"strings"
)

// PolicyManager is responsible for storing and managing policy/client data
type PolicyManager interface {
	Evaluate(*authorization.ActionMsg) Action
	Policies(string) []policy.Policy
	Client(string) *client.Client
}

// Manager is responsible for storing and managing policy/client data
type Manager struct {
	// clients maps client_name -> client_config
	clients map[string]*client.Client
	// services maps service -> client_config
	services map[string]*client.Client
	// policies maps client_name -> list of policies
	policies map[string][]policy.Policy
}

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type   policy.Type
	Client *client.Client
}

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *Manager) Evaluate(action *authorization.ActionMsg) Action {
	// Get destination service
	destinationService := strings.TrimSuffix(action.Service, ".svc.cluster.local")

	// Get policy to enforce
	policies := m.Policies(destinationService)
	if policies == nil || len(policies) == 0 {
		return Action{
			Type:   policy.NONE,
			Client: nil,
		}
	}
	policyToEnforce := policies[0]
	client := m.Client(policyToEnforce.ClientName)
	return Action{
		Type:   policyToEnforce.Type,
		Client: client,
	}
}

// Policies returns the policies associated with a particular service
func (m *Manager) Policies(svc string) []policy.Policy {
	return m.policies[svc]
}

// Client returns the client instance given its name
func (m *Manager) Client(clientName string) *client.Client {
	return m.clients[clientName]
}

// New creates a PolicyManager
func New() PolicyManager {
	// Temporary Hardcode Setup
	cfg := client.Config{
		Name:         "f82dc917-3047-4af1-9775-60e0e07e1fac",
		ClientID:     "4da82297-b0ce-45e0-b17b-4a96e965b609",
		Secret:       "ODYxYjJhY2EtZTMwNi00ZmQ2LTk5ZTgtMjgwNzViYTM4Mjhj",
		DiscoveryURL: "https://appid-oauth.eu-gb.bluemix.net/oauth/v3/f82dc917-3047-4af1-9775-60e0e07e1fac/.well-known/openid-configuration",
		Type:         client.OIDC,
	}
	p := policy.Policy{
		ClientName: "f82dc917-3047-4af1-9775-60e0e07e1fac",
		Dest:       "any",
		Type:       policy.API,
	}
	ps := []policy.Policy{p}
	c := client.New(cfg)
	clients := make(map[string]*client.Client)
	clients[c.Name] = &c
	policies := make(map[string][]policy.Policy)
	policies[p.Dest] = ps

	return &Manager{
		clients:  clients,
		services: make(map[string]*client.Client),
		policies: policies,
	}
}

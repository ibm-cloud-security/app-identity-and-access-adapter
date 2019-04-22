// Package manager is responsible for monitoring and maintaining authn/z policies
package manager

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy"
)

type PolicyManager interface {
	IsRequired(string) bool
	GetPolicies(string) []policy.Policy
	GetClient(string) client.Client
}

// Policy Manager
type Manager struct {
	// clients maps client_name -> client_config
	clients map[string]*client.Client
	// services maps service -> client_config
	services map[string]*client.Client
	// policies maps client_name -> list of policies
	policies map[string][]policy.Policy
}

func (m *Manager) IsRequired(svc string) bool {
	return true
}

func (m *Manager) GetPolicies(svc string) []policy.Policy {
	return m.policies[svc]
}

func (m *Manager) GetClient(clientName string) client.Client {
	return *m.clients[clientName]
}

func New() *Manager {
	// Temporary Hardcode Setup
	cfg := client.Config{
		Name:         "71b34890-a94f-4ef2-a4b6-ce094aa68092",
		ClientID:     "7a2a8cb8-774e-49e0-90c2-425f03aecec6",
		Secret:       "Y2VjNGIwNjctOTEyMy00NTQ0LTg0NjgtZTJjYTA3MjNhYjFl",
		DiscoveryURL: "https://appid-oauth.ng.bluemix.net/oauth/v3/798288dc-79cb-4faf-9825-dad68cd4ed6f/oidc",
		Type:         client.OIDC,
	}
	p := policy.Policy{
		ClientName: "71b34890-a94f-4ef2-a4b6-ce094aa68092",
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

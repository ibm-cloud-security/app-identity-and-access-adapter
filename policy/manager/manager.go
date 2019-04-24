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

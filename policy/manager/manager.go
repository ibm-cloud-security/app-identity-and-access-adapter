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
	return &Manager{
		clients:  make(map[string]*client.Client),
		services: make(map[string]*client.Client),
		policies: make(map[string][]policy.Policy),
	}
}

package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/pathtrie"
)

// LocalStore is responsible for storing and managing policy/client data
type LocalStore struct {
	// clients maps client_name -> client_config
	clients map[string]client.Client // oidc config ClientName:Client
	// policies maps endpoint -> list of actions
	policies map[policy.Service]pathtrie.Trie
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string][]policy.Mapping
	// keysets maps client_name -> keyset
	keysets map[string]keyset.KeySet
}

// New creates a new local store
func New() Store {
	return &LocalStore{
		clients:        make(map[string]client.Client),
		policies:       make(map[policy.Service]pathtrie.Trie),
		policyMappings: make(map[string][]policy.Mapping),
		keysets:        make(map[string]keyset.KeySet),
	}
}

// GetKeySet returns the JWKS for the given client_name
func (s *LocalStore) GetKeySet(clientName string) keyset.KeySet {
	if s.keysets != nil {
		return s.keysets[clientName]
	}
	return nil
}

// AddKeySet stores the JWKS for the given client_name
func (s *LocalStore) AddKeySet(clientName string, jwks keyset.KeySet) {
	if s.keysets == nil {
		s.keysets = make(map[string]keyset.KeySet)
	}
	s.keysets[clientName] = jwks
}

// DeleteKeySet deletes the JWKS for the given client_name
func (s *LocalStore) DeleteKeySet(clientName string) {
	if s.keysets != nil {
		delete(s.keysets, clientName)
	}
}

// GetClient returns the Client instance for the given client_name
func (s *LocalStore) GetClient(clientName string) client.Client {
	if s.clients != nil {
		return s.clients[clientName]
	}
	return nil
}

// AddClient stores the Client instance for the given client_name
func (s *LocalStore) AddClient(clientName string, clientObject client.Client) {
	if s.clients == nil {
		s.clients = make(map[string]client.Client)
	}
	s.clients[clientName] = clientObject
}

// DeleteClient deletes the Client instance for the given client_name
func (s *LocalStore) DeleteClient(clientName string) {
	if s.clients != nil {
		delete(s.clients, clientName)
	}
}

// GetPolicies returns the policies stored on given endpoint
func (s *LocalStore) GetPolicies(endpoint policy.Endpoint) policy.RoutePolicy {
	if s.policies != nil && s.policies[endpoint.Service] != nil {
		actions, ok := (s.policies[endpoint.Service].GetActions(endpoint.Path)).(policy.Actions)
		if ok {
			result, present := actions[endpoint.Method]
			if present { // found actions for method
				return result
			}
			result, present = actions[policy.ALL]
			if present { // check if actions are set for ALL
				return result
			}
		}
	}
	return policy.NewRoutePolicy()
}

// SetPolicies stores policies on given endpoint
func (s *LocalStore) SetPolicies(endpoint policy.Endpoint, actions policy.RoutePolicy) {
	if s.policies == nil {
		s.policies = make(map[policy.Service]pathtrie.Trie)
	}
	if s.policies[endpoint.Service] == nil {
		s.policies[endpoint.Service] = pathtrie.NewPathTrie()
	}

	if obj, ok := (s.policies[endpoint.Service].GetActions(endpoint.Path)).(policy.Actions); ok {
		obj[endpoint.Method] = actions
	} else {
		obj := policy.NewActions()
		obj[endpoint.Method] = actions
		s.policies[endpoint.Service].Put(endpoint.Path, obj)
	}
}

// GetPolicyMapping returns policy locations for a given policy id
func (s *LocalStore) GetPolicyMapping(policy string) []policy.Mapping {
	if s.policyMappings != nil {
		return s.policyMappings[policy]
	}
	return nil
}

// DeletePolicyMapping deletes a policy mapping
func (s *LocalStore) DeletePolicyMapping(policy string) {
	if s.policyMappings != nil {
		delete(s.policyMappings, policy)
	}
}

// AddPolicyMapping adds a policy mapping to the store
func (s *LocalStore) AddPolicyMapping(name string, mapping []policy.Mapping) {
	if s.policyMappings == nil {
		s.policyMappings = make(map[string][]policy.Mapping)
	}
	s.policyMappings[name] = mapping
}

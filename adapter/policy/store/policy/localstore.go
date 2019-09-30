package policy

import (
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/client"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy/store/pathtrie"
)

// LocalStore is responsible for storing and managing policy/client data
type LocalStore struct {
	// clients maps client_name -> client_config
	clients map[string]client.Client // oidc config ClientName:Client
	// policies maps endpoint -> list of actions
	policies map[policy.Service]pathtrie.Trie
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string][]policy.PolicyMapping
	keysets        map[string]keyset.KeySet // jwt config ClientName:keyset
}

// New creates a new local store
func New() PolicyStore {
	return &LocalStore{
		clients:        make(map[string]client.Client),
		policies:       make(map[policy.Service]pathtrie.Trie),
		policyMappings: make(map[string][]policy.PolicyMapping),
		keysets:        make(map[string]keyset.KeySet),
	}
}

func (l *LocalStore) GetKeySet(clientName string) keyset.KeySet {
	if l.keysets != nil {
		return l.keysets[clientName]
	}
	return nil
}

func (l *LocalStore) AddKeySet(clientName string, jwks keyset.KeySet) {
	if l.keysets == nil {
		l.keysets = make(map[string]keyset.KeySet)
	}
	l.keysets[clientName] = jwks
}

func (l *LocalStore) DeleteKeySet(clientName string) {
	if l.keysets != nil {
		delete(l.keysets, clientName)
	}
}

func (l *LocalStore) GetClient(clientName string) client.Client {
	if l.clients != nil {
		return l.clients[clientName]
	}
	return nil
}

func (l *LocalStore) AddClient(clientName string, clientObject client.Client) {
	if l.clients == nil {
		l.clients = make(map[string]client.Client)
	}
	l.clients[clientName] = clientObject
}

func (l *LocalStore) DeleteClient(clientName string) {
	if l.clients != nil {
		delete(l.clients, clientName)
	}
}

func (l *LocalStore) GetPolicies(endpoint policy.Endpoint) policy.RoutePolicy {
	if l.policies != nil && l.policies[endpoint.Service] != nil {
		actions, ok := (l.policies[endpoint.Service].GetActions(endpoint.Path, true)).(policy.Actions)
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

func (l *LocalStore) SetPolicies(endpoint policy.Endpoint, actions policy.RoutePolicy) {
	if l.policies == nil {
		l.policies = make(map[policy.Service]pathtrie.Trie)
	}
	if l.policies[endpoint.Service] == nil {
		l.policies[endpoint.Service] = pathtrie.NewPathTrie()
	}

	if obj, ok := (l.policies[endpoint.Service].GetActions(endpoint.Path, false)).(policy.Actions); ok {
		obj[endpoint.Method] = actions
		l.policies[endpoint.Service].Put(endpoint.Path, obj)
	} else {
		obj := policy.NewActions()
		obj[endpoint.Method] = actions
		l.policies[endpoint.Service].Put(endpoint.Path, obj)
	}
}

func (l *LocalStore) DeletePolicies(endpoint policy.Endpoint) {
	if l.policies == nil {
		l.policies[endpoint.Service].Delete(endpoint.Path)
	}
}

func (l *LocalStore) GetPolicyMapping(policy string) []policy.PolicyMapping {
	if l.policyMappings != nil {
		return l.policyMappings[policy]
	}
	return nil
}

func (l *LocalStore) DeletePolicyMapping(policy string) {
	if l.policyMappings != nil {
		delete(l.policyMappings, policy)
	}
}

func (l *LocalStore) AddPolicyMapping(name string, mapping []policy.PolicyMapping) {
	if l.policyMappings == nil {
		l.policyMappings = make(map[string][]policy.PolicyMapping)
	}
	l.policyMappings[name] = mapping
}

package policy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
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

func (l *LocalStore) GetPolicies(endpoint policy.Endpoint) []v1.PathPolicy {
	if l.policies != nil && l.policies[endpoint.Service] != nil {
		actions, ok := (l.policies[endpoint.Service].GetActions(endpoint.Path)).(policy.Actions)
		if ok {
			result := actions[endpoint.Method]
			if result != nil { // found actions for method
				return result
			}
			result = actions[policy.ALL]
			if result != nil { // check if actions are set for ALL
				return result
			}
		}
	}
	return []v1.PathPolicy{}
}

func (s *LocalStore) SetPolicies(endpoint policy.Endpoint, actions []v1.PathPolicy) {
	if s.policies == nil {
		s.policies = make(map[policy.Service]pathtrie.Trie)
	}
	if s.policies[endpoint.Service] == nil {
		s.policies[endpoint.Service] = pathtrie.NewPathTrie()
	}

	if obj, ok := (s.policies[endpoint.Service].GetActions(endpoint.Path)).(policy.Actions); ok {
		obj[endpoint.Method] = actions
	} else {
		obj := policy.Actions{}
		obj[endpoint.Method] = actions
		s.policies[endpoint.Service].Put(endpoint.Path, obj)
	}
}

func (s *LocalStore) GetPolicyMapping(policy string) []policy.PolicyMapping {
	if s.policyMappings != nil {
		return s.policyMappings[policy]
	}
	return nil
}

func (s *LocalStore) DeletePolicyMapping(policy string) {
	if s.policyMappings != nil {
		delete(s.policyMappings, policy)
	}
}

func (s *LocalStore) AddPolicyMapping(name string, mapping []policy.PolicyMapping) {
	if s.policyMappings == nil {
		s.policyMappings = make(map[string][]policy.PolicyMapping)
	}
	s.policyMappings[name] = mapping
}

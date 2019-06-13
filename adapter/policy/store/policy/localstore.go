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
	policies pathtrie.Trie
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string]*policy.PolicyMapping
	keysets map[string]keyset.KeySet // jwt config ClientName:keyset
}

// New creates a new local store
func New() PolicyStore {
	return &LocalStore{
		clients:        make(map[string]client.Client),
		policies:       pathtrie.NewPathTrie(),
		policyMappings: make(map[string]*policy.PolicyMapping),
		keysets:        make(map[string]keyset.KeySet),
	}
}

func (l *LocalStore) GetKeySet(jwksURL string) keyset.KeySet {
	if l.keysets != nil {
		return l.keysets[jwksURL]
	}
	return nil
}

func (l *LocalStore) AddKeySet(jwksURL string, jwks keyset.KeySet) {
	if l.keysets != nil {
		l.keysets = make(map[string]keyset.KeySet)
	}
	l.keysets[jwksURL] = jwks
}

func (l *LocalStore) GetClient(clientName string) client.Client {
	if l.clients != nil {
		return l.clients[clientName]
	}
	return nil
}

func (l *LocalStore) AddClient(clientName string, clientObject client.Client) {
	if l.clients != nil {
		l.clients = make(map[string]client.Client)
	}
	l.clients[clientName] = clientObject
}

func (l *LocalStore) GetPolicies(endpoint string) policy.Actions {
	result, ok := (l.policies.GetActions(endpoint)).(policy.Actions)
	if ok {
		return result
	}
	return policy.Actions{ Actions: []policy.Action{} }
}

func (l *LocalStore) SetPolicies(endpoint string, action policy.Actions) {
	l.policies.Put(endpoint, action)
}

func (s *LocalStore) GetPolicyMapping(policy string) *policy.PolicyMapping {
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

func (s *LocalStore) AddPolicyMapping(name string, mapping *policy.PolicyMapping) {
	if s.policyMappings == nil {
		s.policyMappings = make(map[string]*policy.PolicyMapping)
	}
	s.policyMappings[name] = mapping
}

package store

import (
	"reflect"

	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/client"
	"ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy"
)

// LocalStore is responsible for storing and managing policy/client data
type LocalStore struct {
	// clients maps client_name -> client_config
	clients map[string]*client.Client
	// authserver maps jwksurl -> AuthorizationServers
	authservers map[string]authserver.AuthorizationServer
	// policies maps endpoint -> list of policies
	apiPolicies map[policy.Endpoint][]v1.JwtPolicySpec
	// policies maps endpoint -> list of policies
	webPolicies map[policy.Endpoint][]v1.OidcPolicySpec
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string]*policy.PolicyMapping
}

// New creates a new local store
func New() PolicyStore {
	return &LocalStore{
		clients:        make(map[string]*client.Client),
		authservers:    make(map[string]authserver.AuthorizationServer),
		apiPolicies:    make(map[policy.Endpoint][]v1.JwtPolicySpec),
		webPolicies:    make(map[policy.Endpoint][]v1.OidcPolicySpec),
		policyMappings: make(map[string]*policy.PolicyMapping),
	}
}

func (l *LocalStore) GetClient(clientName string) *client.Client {
	if l.clients != nil {
		return l.clients[clientName]
	}
	return nil
}

func (l *LocalStore) AddClient(clientName string, clientObject *client.Client) {
	if l.clients != nil {
		l.clients = make(map[string]*client.Client)
	}
	l.clients[clientName] = clientObject

}
func (l *LocalStore) GetAuthServer(serverName string) authserver.AuthorizationServer {
	if l.authservers != nil {
		return l.authservers[serverName]
	}
	return nil
}

func (l *LocalStore) AddAuthServer(serverName string, server authserver.AuthorizationServer) {
	if l.authservers != nil {
		l.authservers = make(map[string]authserver.AuthorizationServer)
	}
	l.authservers[serverName] = server
}
func (l *LocalStore) GetApiPolicies(ep policy.Endpoint) []v1.JwtPolicySpec {
	if l.apiPolicies != nil {
		return l.apiPolicies[ep]
	}
	return nil
}

func (s *LocalStore) SetApiPolicy(ep policy.Endpoint, spec v1.JwtPolicySpec) {
	if s.apiPolicies == nil {
		s.apiPolicies = make(map[policy.Endpoint][]v1.JwtPolicySpec)
	}
	if s.apiPolicies[ep] == nil {
		s.apiPolicies[ep] = make([]v1.JwtPolicySpec, 0)
	}
	s.apiPolicies[ep] = append(s.apiPolicies[ep], spec)
}

func (s *LocalStore) DeleteApiPolicy(ep policy.Endpoint, obj interface{}) {
	loc := -1
	for index, value := range s.apiPolicies[ep] {
		if reflect.DeepEqual(value, obj) {
			loc = index
			break
		}
	}
	if loc >= 0 {
		copy(s.apiPolicies[ep][loc:], s.apiPolicies[ep][loc+1:])
		s.apiPolicies[ep] = s.apiPolicies[ep][:len(s.apiPolicies[ep])-1]
	}
}

func (s *LocalStore) SetApiPolicies(ep policy.Endpoint, policies []v1.JwtPolicySpec) {
	if s.apiPolicies == nil {
		s.apiPolicies = make(map[policy.Endpoint][]v1.JwtPolicySpec)
	}
	if s.apiPolicies[ep] == nil {
		s.apiPolicies[ep] = make([]v1.JwtPolicySpec, 0)
	}
	s.apiPolicies[ep] = append(s.apiPolicies[ep], policies...)
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

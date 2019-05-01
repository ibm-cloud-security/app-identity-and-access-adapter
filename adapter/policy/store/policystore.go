package store

import (
	"ibmcloudappid/adapter/authserver"
	"ibmcloudappid/adapter/client"
	v1 "ibmcloudappid/adapter/pkg/apis/policies/v1"
	"ibmcloudappid/adapter/policy/handler"
	"reflect"
)

// Manager is responsible for storing and managing policy/client data
type LocalStore struct {
	// clients maps client_name -> client_config
	clients map[string]*client.Client
	// authserver maps jwksurl -> AuthorizationServers
	authservers map[string]authserver.AuthorizationServer
	// policies maps endpoint -> list of policies
	apiPolicies map[handler.Endpoint][]v1.JwtPolicySpec
	// policies maps endpoint -> list of policies
	webPolicies map[handler.Endpoint][]v1.OidcPolicySpec
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string]*handler.PolicyMapping
}

func New() PolicyStore {
	return &LocalStore{
		clients:     make(map[string]*client.Client),
		authservers: make(map[string]authserver.AuthorizationServer),
		apiPolicies: make(map[handler.Endpoint][]v1.JwtPolicySpec),
		webPolicies: make(map[handler.Endpoint][]v1.OidcPolicySpec),
		policyMappings: make(map[string]*handler.PolicyMapping),
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
func (l *LocalStore) GetApiPolicies(ep handler.Endpoint) []v1.JwtPolicySpec {
	if l.apiPolicies != nil {
		return l.apiPolicies[ep]
	}
	return nil
}


func (s *LocalStore) SetApiPolicy(ep handler.Endpoint, policy v1.JwtPolicySpec) {
	if s.apiPolicies == nil {
		s.apiPolicies = make(map[handler.Endpoint][]v1.JwtPolicySpec)
	}
	if s.apiPolicies[ep] == nil {
		s.apiPolicies[ep] = make([]v1.JwtPolicySpec, 0)
	}
	s.apiPolicies[ep] = append(s.apiPolicies[ep], policy)
}
//DeleteApiPolicy(ep handler.Endpoint)

func (s *LocalStore) DeleteApiPolicy(ep handler.Endpoint, obj interface{}) {
	loc := -1
	for index , value := range s.apiPolicies[ep] {
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

func (s *LocalStore) SetApiPolicies(ep handler.Endpoint, policies []v1.JwtPolicySpec) {
	if s.apiPolicies == nil {
		s.apiPolicies = make(map[handler.Endpoint][]v1.JwtPolicySpec)
	}
	if s.apiPolicies[ep] == nil {
		s.apiPolicies[ep] = make([]v1.JwtPolicySpec, 0)
	}
	s.apiPolicies[ep] = append(s.apiPolicies[ep], policies...)
}


func (s *LocalStore) GetPolicyMapping(policy string) *handler.PolicyMapping {
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

func (s *LocalStore) AddPolicyMapping(policy string, mapping *handler.PolicyMapping) {
	if s.policyMappings == nil {
		s.policyMappings = make(map[string]*handler.PolicyMapping)
	}
	s.policyMappings[policy] = mapping
}
package store

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
)

// LocalStore is responsible for storing and managing policy/client data
type LocalStore struct {
	// clients maps client_name -> client_config
	clients map[string]client.Client
	// authserver maps jwksurl -> AuthorizationServers
	authservers map[string]authserver.AuthorizationServer
	// policies maps endpoint -> list of policies
	apiPolicies map[policy.Endpoint]policy.Action
	// policies maps endpoint -> list of policies
	webPolicies map[policy.Endpoint]policy.Action
	// policyMappings maps policy(namespace/name) -> list of created endpoints
	policyMappings map[string]*policy.PolicyMapping
	keysets        map[string]keyset.KeySet
}

// New creates a new local store
func New() PolicyStore {
	return &LocalStore{
		clients:        make(map[string]client.Client),
		authservers:    make(map[string]authserver.AuthorizationServer),
		apiPolicies:    make(map[policy.Endpoint]policy.Action),
		webPolicies:    make(map[policy.Endpoint]policy.Action),
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

func (l *LocalStore) GetApiPolicies(ep policy.Endpoint) *policy.Action {

	if l.apiPolicies == nil {
		return nil
	}

	if action, ok := l.apiPolicies[ep]; ok {
		return &action
	} else {
		return nil
	}
}

func (s *LocalStore) SetApiPolicy(ep policy.Endpoint, action policy.Action) {
	if s.apiPolicies == nil {
		s.apiPolicies = make(map[policy.Endpoint]policy.Action)
	}

	s.apiPolicies[ep] = action
}

func (s *LocalStore) DeleteApiPolicy(ep policy.Endpoint, obj interface{}) {
	if s.apiPolicies != nil {
		delete(s.apiPolicies, ep)
	}
}

//TODO
/*func (s *LocalStore) SetApiPolicies(ep policy.Endpoint, policies engine.Action) {
	if s.apiPolicies == nil {
		s.apiPolicies = make(map[policy.Endpoint] engine.Action)
	}

	s.apiPolicies[ep] = policies
}*/

func (l *LocalStore) GetWebPolicies(ep policy.Endpoint) *policy.Action {

	if l.webPolicies == nil {
		return nil
	}

	if action, ok := l.webPolicies[ep]; ok {
		return &action
	} else {
		return nil
	}
}

func (s *LocalStore) SetWebPolicy(ep policy.Endpoint, action policy.Action) {
	if s.webPolicies == nil {
		s.webPolicies = make(map[policy.Endpoint]policy.Action)
	}

	s.webPolicies[ep] = action
}

func (s *LocalStore) DeleteWebPolicy(ep policy.Endpoint, obj interface{}) {
	if s.webPolicies != nil {
		delete(s.webPolicies, ep)
	}
}

/*func (s *LocalStore) SetWebPolicies(ep policy.Endpoint, actions []policy.Action) {
	if s.webPolicies == nil {
		s.webPolicies = make(map[policy.Endpoint][]v1.OidcPolicySpec)
	}
	if s.webPolicies[ep] == nil {
		s.webPolicies[ep] = make([]v1.OidcPolicySpec, 0)
	}
	s.webPolicies[ep] = append(s.webPolicies[ep], policies...)
}*/

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

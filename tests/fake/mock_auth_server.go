package fake

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
)

type MockAuthServer struct {
	Keys keyset.KeySet
	Url  string
}

func (m *MockAuthServer) JwksEndpoint() string          { return m.Url }
func (m *MockAuthServer) TokenEndpoint() string         { return m.Url }
func (m *MockAuthServer) AuthorizationEndpoint() string { return m.Url }
func (m *MockAuthServer) KeySet() keyset.KeySet {
	return m.Keys
}
func (m *MockAuthServer) SetKeySet(keyset.KeySet) {}
func (m *MockAuthServer) GetTokens(authnMethod string, clientID string, clientSecret string, authorizationCode string, redirectURI string) (*authserver.TokenResponse, error) {
	return nil, nil
}

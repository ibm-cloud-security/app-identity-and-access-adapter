package fake

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
)

type AuthServer struct {
	Keys         keyset.KeySet
	Url          string
	JwksURL      string
	TknEndpoint  string
	AuthEndpoint string
}

func NewAuthServer() *AuthServer {
	return &AuthServer{
		JwksURL:      "https://auth.com/publickeys",
		TknEndpoint:  "https://auth.com/token",
		AuthEndpoint: "https://auth.com/authorization",
		Keys:         &KeySet{},
	}
}
func (m *AuthServer) JwksEndpoint() string {
	return m.JwksURL
}

func (m *AuthServer) TokenEndpoint() string {
	return m.TknEndpoint
}

func (m *AuthServer) AuthorizationEndpoint() string {
	return m.AuthEndpoint
}

func (m *AuthServer) KeySet() keyset.KeySet {
	return m.Keys
}

func (m *AuthServer) SetKeySet(k keyset.KeySet) {
	m.Keys = k
}

func (m *AuthServer) GetTokens(authnMethod string, clientID string, clientSecret string, authorizationCode string, redirectURI string, refreshToken string) (*authserver.TokenResponse, error) {
	return nil, nil
}

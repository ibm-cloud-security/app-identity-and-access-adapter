package fake

import "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"

type TokenResponse struct {
	Res *authserver.TokenResponse
	Err error
}
type MockClient struct {
	Server        authserver.AuthorizationServer
	TokenResponse *TokenResponse
}

func (m *MockClient) Name() string                                        { return "name" }
func (m *MockClient) ID() string                                          { return "id" }
func (m *MockClient) Secret() string                                      { return "secret" }
func (m *MockClient) AuthorizationServer() authserver.AuthorizationServer { return m.Server }
func (m *MockClient) ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error) {
	return m.TokenResponse.Res, m.TokenResponse.Err
}

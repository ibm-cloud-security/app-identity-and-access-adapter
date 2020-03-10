package fake

import (
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver"
)

type TokenResponse struct {
	Res *authserver.TokenResponse
	Err error
}

type Client struct {
	Server        authserver.AuthorizationServerService
	TokenResponse *TokenResponse
	ClientName    string
	ClientID      string
	ClientSecret  string
	Scopes        []string
}

func NewClient(tokenResponse *TokenResponse) *Client {
	return &Client{
		Server:        NewAuthServer(),
		ClientName:    "name",
		ClientID:      "id",
		ClientSecret:  "secret",
		TokenResponse: tokenResponse,
	}
}

func (m *Client) Name() string {
	return m.ClientName
}

func (m *Client) ID() string {
	return m.ClientID
}

func (m *Client) Secret() string {
	return m.ClientSecret
}

func (m *Client) Scope() string {
	return "openid profile email"
}

func (m *Client) AuthorizationServer() authserver.AuthorizationServerService {
	return m.Server
}

func (m *Client) ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error) {
	return m.TokenResponse.Res, m.TokenResponse.Err
}

func (m *Client) RefreshToken(refreshToken string) (*authserver.TokenResponse, error) {
	return m.TokenResponse.Res, m.TokenResponse.Err
}

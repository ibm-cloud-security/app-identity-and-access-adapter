package fake

import "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"

type TokenResponse struct {
	Res *authserver.TokenResponse
	Err error
}

type Client struct {
	Server        authserver.AuthorizationServer
	TokenResponse *TokenResponse
	ClientName    string
	ClientID      string
	ClientSecret  string
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

func (m *Client) AuthorizationServer() authserver.AuthorizationServer {
	return m.Server
}

func (m *Client) ExchangeGrantCode(code string, redirectURI string) (*authserver.TokenResponse, error) {
	return m.TokenResponse.Res, m.TokenResponse.Err
}

func (m *Client) RefreshToken(refreshToken string) (*authserver.TokenResponse, error) {
	return m.TokenResponse.Res, m.TokenResponse.Err
}

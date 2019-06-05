package framework

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
)

type OAuthManager struct {
	ClientID       string
	ClientSecret   string
	OAuthServerURL string
	Tokens         *authserver.TokenResponse
	client         *networking.HTTPClient
}

func (m *OAuthManager) OK() bool {
	return m.ClientID != "" && m.ClientSecret != "" && m.OAuthServerURL != "" && m.client != nil
}

func (m *OAuthManager) TokenURL() string {
	return m.OAuthServerURL + "/token"
}

func (m *OAuthManager) PublicKeysURL() string {
	return m.OAuthServerURL + "/publickeys"
}

func (m *OAuthManager) DiscoveryURL() string {
	return m.OAuthServerURL + "/.well-known/openid-configuration"
}

func (m *OAuthManager) ROP(username string, password string) error {
	form := url.Values{}
	form.Add("client_id", m.ClientID)
	form.Add("grant_type", "password")
	form.Add("username", username)
	form.Add("password", password)

	req, err := http.NewRequest("POST", m.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		zap.L().Warn("Could not serialize HTTP request", zap.Error(err))
		return err
	}

	req.SetBasicAuth(m.ClientID, m.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tokenResponse authserver.TokenResponse
	if err := m.client.Do(req, http.StatusOK, &tokenResponse); err != nil {
		zap.L().Info("Failed to retrieve tokens", zap.Error(err))
		return err
	}

	m.Tokens = &tokenResponse
	return nil
}

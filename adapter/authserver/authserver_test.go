package authserver

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	authURL           = "https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/authorization"
	tokenURL          = "https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/token"
	publicKeyURL      = "https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/publickeys"
	discoveryResponse = "{\"issuer\": \"https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092\",\"authorization_endpoint\": \"https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/authorization\",\"token_endpoint\": \"https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/token\",\"jwks_uri\": \"https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/publickeys\",\"subject_types_supported\": [\"public\"], \"id_token_signing_alg_values_supported\": [\"RS256\"], \"userinfo_endpoint\": \"https://eu-gb.appid.cloud.ibm.com/oauth/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092/userinfo\",\"scopes_supported\": [\"openid\"], \"response_types_supported\": [\"code\"], \"claims_supported\": [\"iss\",\"aud\",\"exp\",\"tenant\",\"iat\",\"sub\",\"nonce\",\"amr\",\"oauth_client\"], \"grant_types_supported\": [\"authorization_code\",\"password\",\"refresh_token\",\"client_credentials\",\"urn:ietf:params:oauth:grant-type:jwt-bearer\"], \"profiles_endpoint\": \"https://eu-gb.appid.cloud.ibm.com\",\"management_endpoint\": \"https://eu-gb.appid.cloud.ibm.com/management/v4/71b34890-a94f-4ef2-a4b6-ce094aa68092\",\"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"}"
)

func TestAuthServerNew(t *testing.T) {

	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(discoveryResponse))
	})

	// Start a local HTTP server
	s := httptest.NewServer(h)
	defer s.Close()

	server := New(s.URL)
	assert.NotNil(t, server)
	remoteServer := server.(*RemoteServer)
	assert.NotNil(t, remoteServer.httpclient)
	assert.True(t, remoteServer.initialized)
	assert.Equal(t, publicKeyURL, server.KeySet().PublicKeyURL())
	assert.Equal(t, publicKeyURL, server.JwksEndpoint())
	assert.Equal(t, tokenURL, server.TokenEndpoint())
	assert.Equal(t, authURL, server.AuthorizationEndpoint())
}

func TestSetKeySet(t *testing.T) {
	server := New("")
	assert.Nil(t, server.KeySet())
	server.SetKeySet(keyset.New("", nil))
	assert.NotNil(t, server.KeySet())
}

func TestInitialize(t *testing.T) {

	tests := []struct {
		statusCode int
		response   string
		err        string
	}{
		{
			400,
			"{}",
			"status code: 400",
		},
		{
			200,
			"",
			"EOF",
		},
	}
	for _, test := range tests {
		// Start a local HTTP server
		h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(test.statusCode)
			w.Write([]byte(test.response))
		})
		s := httptest.NewServer(h)
		server := &RemoteServer{discoveryURL: s.URL, httpclient: &networking.HTTPClient{Client: s.Client()}}
		err := server.initialize()
		if !strings.Contains(err.Error(), test.err) {
			t.Fail()
		}
		s.Close()
	}
}

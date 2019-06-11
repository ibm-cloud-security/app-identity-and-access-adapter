package authserver

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
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
		err        error
	}{
		{
			400,
			"{}",
			errors.New("status code: 400"),
		},
		{
			200,
			"{\n  \"issuer\": \"https://eu-gb.appid.test.cloud.ibm.com/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"authorization_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/authorization\",\n  \"token_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/token\",\n  \"jwks_uri\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/publickeys\",\n  \"subject_types_supported\": [\n    \"public\"\n  ],\n  \"id_token_signing_alg_values_supported\": [\n    \"RS256\"\n  ],\n  \"userinfo_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/userinfo\",\n  \"scopes_supported\": [\n    \"openid\"\n  ],\n  \"response_types_supported\": [\n    \"code\"\n  ],\n  \"claims_supported\": [\n    \"iss\",\n    \"aud\",\n    \"exp\",\n    \"tenant\",\n    \"iat\",\n    \"sub\",\n    \"nonce\",\n    \"amr\",\n    \"oauth_client\"\n  ],\n  \"grant_types_supported\": [\n    \"authorization_code\",\n    \"password\",\n    \"refresh_token\",\n    \"client_credentials\",\n    \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n  ],\n  \"profiles_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net\",\n  \"management_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/management/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"\n}",
			nil,
		},
		{
			200,
			"{\n \"authorization_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/authorization\",\n  \"token_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/token\",\n  \"jwks_uri\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/publickeys\",\n  \"subject_types_supported\": [\n    \"public\"\n  ],\n  \"id_token_signing_alg_values_supported\": [\n    \"RS256\"\n  ],\n  \"userinfo_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/userinfo\",\n  \"scopes_supported\": [\n    \"openid\"\n  ],\n  \"response_types_supported\": [\n    \"code\"\n  ],\n  \"claims_supported\": [\n    \"iss\",\n    \"aud\",\n    \"exp\",\n    \"tenant\",\n    \"iat\",\n    \"sub\",\n    \"nonce\",\n    \"amr\",\n    \"oauth_client\"\n  ],\n  \"grant_types_supported\": [\n    \"authorization_code\",\n    \"password\",\n    \"refresh_token\",\n    \"client_credentials\",\n    \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n  ],\n  \"profiles_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net\",\n  \"management_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/management/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"\n}",
			errors.New("invalid discovery config: missing `issuer`"),
		},
		{
			200,
			"{\n  \"issuer\": \"https://eu-gb.appid.test.cloud.ibm.com/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\"token_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/token\",\n  \"jwks_uri\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/publickeys\",\n  \"subject_types_supported\": [\n    \"public\"\n  ],\n  \"id_token_signing_alg_values_supported\": [\n    \"RS256\"\n  ],\n  \"userinfo_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/userinfo\",\n  \"scopes_supported\": [\n    \"openid\"\n  ],\n  \"response_types_supported\": [\n    \"code\"\n  ],\n  \"claims_supported\": [\n    \"iss\",\n    \"aud\",\n    \"exp\",\n    \"tenant\",\n    \"iat\",\n    \"sub\",\n    \"nonce\",\n    \"amr\",\n    \"oauth_client\"\n  ],\n  \"grant_types_supported\": [\n    \"authorization_code\",\n    \"password\",\n    \"refresh_token\",\n    \"client_credentials\",\n    \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n  ],\n  \"profiles_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net\",\n  \"management_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/management/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"\n}",
			errors.New("invalid discovery config: missing `authorization_endpoint`"),
		},
		{
			200,
			"{\n  \"issuer\": \"https://eu-gb.appid.test.cloud.ibm.com/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"authorization_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/authorization\",\n \"jwks_uri\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/publickeys\",\n  \"subject_types_supported\": [\n    \"public\"\n  ],\n  \"id_token_signing_alg_values_supported\": [\n    \"RS256\"\n  ],\n  \"userinfo_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/userinfo\",\n  \"scopes_supported\": [\n    \"openid\"\n  ],\n  \"response_types_supported\": [\n    \"code\"\n  ],\n  \"claims_supported\": [\n    \"iss\",\n    \"aud\",\n    \"exp\",\n    \"tenant\",\n    \"iat\",\n    \"sub\",\n    \"nonce\",\n    \"amr\",\n    \"oauth_client\"\n  ],\n  \"grant_types_supported\": [\n    \"authorization_code\",\n    \"password\",\n    \"refresh_token\",\n    \"client_credentials\",\n    \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n  ],\n  \"profiles_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net\",\n  \"management_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/management/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"\n}",
			errors.New("invalid discovery config: missing `token_endpoint`"),
		},
		{
			200,
			"{\n  \"issuer\": \"https://eu-gb.appid.test.cloud.ibm.com/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"authorization_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/authorization\",\n  \"token_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/token\",\n  \"subject_types_supported\": [\n    \"public\"\n  ],\n  \"id_token_signing_alg_values_supported\": [\n    \"RS256\"\n  ],\n  \"userinfo_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/userinfo\",\n  \"scopes_supported\": [\n    \"openid\"\n  ],\n  \"response_types_supported\": [\n    \"code\"\n  ],\n  \"claims_supported\": [\n    \"iss\",\n    \"aud\",\n    \"exp\",\n    \"tenant\",\n    \"iat\",\n    \"sub\",\n    \"nonce\",\n    \"amr\",\n    \"oauth_client\"\n  ],\n  \"grant_types_supported\": [\n    \"authorization_code\",\n    \"password\",\n    \"refresh_token\",\n    \"client_credentials\",\n    \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n  ],\n  \"profiles_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net\",\n  \"management_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/management/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"\n}",
			errors.New("invalid discovery config: missing `jwks_uri`"),
		},
		{
			200,
			"",
			errors.New("EOF"),
		},
		{
			200,
			"{\n  \"issuer\": \"https://eu-gb.appid.test.cloud.ibm.com/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"authorization_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/authorization\",\n  \"token_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/token\",\n  \"jwks_uri\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/oauth/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584/publickeys\",\n  \"subject_types_supported\": [\n    \"public\"\n  ],\n  \"id_token_signing_alg_values_supported\": [\n    \"RS256\"\n  ],\n  \"scopes_supported\": [\n    \"openid\"\n  ],\n  \"response_types_supported\": [\n    \"code\"\n  ],\n  \"claims_supported\": [\n    \"iss\",\n    \"aud\",\n    \"exp\",\n    \"tenant\",\n    \"iat\",\n    \"sub\",\n    \"nonce\",\n    \"amr\",\n    \"oauth_client\"\n  ],\n  \"grant_types_supported\": [\n    \"authorization_code\",\n    \"password\",\n    \"refresh_token\",\n    \"client_credentials\",\n    \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n  ],\n  \"profiles_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net\",\n  \"management_endpoint\": \"https://appid-oauth.stage1.eu-gb.bluemix.net/management/v4/6ed0032a-ac04-4a9f-9d36-7637a16d4584\",\n  \"service_documentation\": \"https://console.bluemix.net/docs/services/appid/index.html\"\n}",
			errors.New("invalid discovery config: missing `userinfo_endpoint`"),
		},
	}
	for _, ts := range tests {
		test := ts // When using parallel sub tests we need a local scope
		t.Run("initialize", func(t2 *testing.T) {
			t2.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(test.statusCode)
				w.Write([]byte(test.response))
			})
			s := httptest.NewServer(h)
			server := &RemoteServer{discoveryURL: s.URL, httpclient: &networking.HTTPClient{Client: s.Client()}}
			err := server.initialize()
			if test.statusCode != 200 {
				if err == nil {
					t2.FailNow()
				}
			} else if test.err != nil {
				require.EqualError(t2, err, test.err.Error())
			} else if err != nil {
				t2.FailNow()
			}
			s.Close()
		})
	}
}

func TestGetTokens(t *testing.T) {

	tests := []struct {
		statusCode int
		response   string
		err        error
	}{
		{
			400,
			"{}",
			errors.New("status code: 400"),
		},
		{
			200,
			"{\n  \"access_token\" : \"2YotnFZFEjr1zCsicMWpAA\",\n  \"token_type\"   : \"bearer\",\n  \"expires_in\"   : 3600,\n  \"scope\"        : \"openid email profile app:read app:write\",\n  \"id_token\"     : \"eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUl...\"\n}",
			nil,
		},
		{
			200,
			"{\n  \"token_type\"   : \"bearer\",\n  \"expires_in\"   : 3600,\n  \"scope\"        : \"openid email profile app:read app:write\",\n  \"id_token\"     : \"eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUl...\"\n}",
			errors.New("invalid token endpoint response: access_token does not exist"),
		},
	}
	for _, ts := range tests {
		test := ts // When using parallel sub tests we need a local scope
		t.Run("TokenResponse", func(t2 *testing.T) {
			t2.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(test.statusCode)
				w.Write([]byte(test.response))
			})
			s := httptest.NewServer(h)
			server := &RemoteServer{DiscoveryConfig: DiscoveryConfig{TokenURL: s.URL}, initialized: true, httpclient: &networking.HTTPClient{Client: s.Client()}}
			_, err := server.GetTokens("client_post_basic", "clientID", "secret", "authcode", "redirect", "")
			if test.statusCode != 200 {
				if err == nil {
					t2.FailNow()
				}
			} else if test.err != nil {
				require.EqualError(t2, err, test.err.Error())
			} else if err != nil {
				t2.FailNow()
			}
			s.Close()
		})
	}
}

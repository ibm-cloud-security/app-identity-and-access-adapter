package webstrategy

import (
	"crypto"
	"errors"
	"github.com/gogo/protobuf/types"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	err "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"github.com/stretchr/testify/assert"
	"istio.io/api/policy/v1beta1"
)

func TestNew(t *testing.T) {
	strategy := New()
	assert.NotNil(t, strategy)
}

func TestHandleNewAuthorizationRequest(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		action         *engine.Action
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
	}{
		{ // Invalid Action Configuration
			generateAuthnzRequest("", "", "", ""),
			&engine.Action{},
			nil,
			"invalid OIDC configuration",
			int32(16),
			errors.New("invalid OIDC configuration"),
		},
		{ // New Authentication
			generateAuthnzRequest("", "", "", ""),
			&engine.Action{
				Client: &mockClient{
					server: &mockAuthServer{keys: &mockKeySet{}},
				},
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Body:    "",
				Headers: map[string]string{"location": "?client_id=id&redirect_uri=https%3A%2F%2Ftest.io%2Fapi%2Foidc%2Fcallback&response_type=code&scope=oidc"},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
	}

	for _, test := range tests {
		api := WebStrategy{
			tokenUtil: MockValidator{
				err: nil,
			},
		}
		r, err := api.HandleAuthnZRequest(test.req, test.action)
		if test.err != nil {
			assert.EqualError(t, err, test.err.Error())
		} else {
			assert.Equal(t, test.code, r.Result.Status.Code)
			assert.Equal(t, test.message, r.Result.Status.Message)
			response := &v1beta1.DirectHttpResponse{}
			for _, detail := range r.Result.Status.Details {
				if types.UnmarshalAny(detail, response) != nil {
					continue
				}
				assert.Equal(t, test.directResponse.Code, response.Code)
				assert.Equal(t, test.directResponse.Headers, response.Headers)
				assert.Equal(t, test.directResponse.Body, response.Body)
			}
		}
	}
}

func TestErrCallback(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		action         *engine.Action
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
	}{
		{ // Err callback with cookies
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint),
			&engine.Action{
				Client: &mockClient{
					server: &mockAuthServer{keys: &mockKeySet{}},
				},
			},
			nil,
			"An err occurred",
			int32(16),
			nil,
		},
		{ // Err callback
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint),
			&engine.Action{
				Client: &mockClient{
					server: &mockAuthServer{keys: &mockKeySet{}},
				},
			},
			nil,
			"An err occurred",
			int32(16),
			nil,
		},
	}

	for _, test := range tests {
		api := WebStrategy{
			tokenUtil: MockValidator{
				err: nil,
			},
		}
		r, err := api.HandleAuthnZRequest(test.req, test.action)
		if test.err != nil {
			assert.EqualError(t, err, test.err.Error())
		} else {
			assert.Equal(t, test.code, r.Result.Status.Code)
			assert.Equal(t, test.message, r.Result.Status.Message)
		}
	}
}

func TestCodeCallback(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
		statusCode     int
		response       string
	}{
		{ // code callback without cookies
			generateAuthnzRequest("", "mycode", "", callbackEndpoint),
			nil,
			"invalid token endpoint response: access_token does not exist",
			int32(16),
			nil,
			200,
			"{}",
		},
	}

	for _, test := range tests {
		// start server
		h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(test.statusCode)
			w.Write([]byte(test.response))
		})
		s := httptest.NewServer(h)

		// Test action
		action := &engine.Action{
			Client: &mockClient{
				server: &mockAuthServer{
					keys: &mockKeySet{},
					url:  s.URL,
				},
			},
		}

		// Test strategy
		api := WebStrategy{
			tokenUtil: MockValidator{
				err: nil,
			},
			httpClient: &networking.HttpClient{Client: s.Client()},
		}

		// Test
		r, err := api.HandleAuthnZRequest(test.req, action)
		if test.err != nil {
			assert.EqualError(t, err, test.err.Error())
		} else {
			assert.Equal(t, test.code, r.Result.Status.Code)
			assert.Equal(t, test.message, r.Result.Status.Message)
		}

		s.Close()
	}
}

func generateAuthnzRequest(cookies string, code string, error string, path string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Request: &authnz.RequestMsg{
				Scheme: "https",
				Host:   "test.io",
				Path:   "/api" + path,
				Headers: &authnz.HeadersMsg{
					Cookies: cookies,
				},
				Params: &authnz.QueryParamsMsg{
					Code:  code,
					Error: error,
				},
			},
			Target: &authnz.TargetMsg{
				Service:   "service",
				Namespace: "namespace",
				Path:      "/api" + path,
				Method:    "GET",
			},
		},
	}
}

type MockValidator struct {
	err *err.OAuthError
}

func (v MockValidator) Validate(tkn string, ks keyset.KeySet, rules []policy.Rule) *err.OAuthError {
	return v.err
}

type mockKeySet struct{}

func (m *mockKeySet) PublicKeyURL() string                  { return "" }
func (m *mockKeySet) PublicKey(kid string) crypto.PublicKey { return nil }

type mockClient struct {
	server authserver.AuthorizationServer
}

func (m *mockClient) Name() string                                        { return "name" }
func (m *mockClient) ID() string                                          { return "id" }
func (m *mockClient) Secret() string                                      { return "secret" }
func (m *mockClient) AuthorizationServer() authserver.AuthorizationServer { return m.server }

type mockAuthServer struct {
	keys keyset.KeySet
	s    *http.Client
	url  string
}

func (m *mockAuthServer) JwksEndpoint() string          { return m.url }
func (m *mockAuthServer) TokenEndpoint() string         { return m.url }
func (m *mockAuthServer) AuthorizationEndpoint() string { return m.url }
func (m *mockAuthServer) KeySet() keyset.KeySet         { return m.keys }
func (m *mockAuthServer) SetKeySet(keyset.KeySet)       {}

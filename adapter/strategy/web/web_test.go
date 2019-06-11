package webstrategy

import (
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"strings"
	"testing"

	"github.com/gogo/protobuf/types"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/config"
	err "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"github.com/stretchr/testify/assert"
	"istio.io/api/policy/v1beta1"
)

func TestNew(t *testing.T) {
	strategy := New(&config.Config{}, k8sfake.NewSimpleClientset())
	assert.NotNil(t, strategy)
	assert.NotNil(t, strategy.(*WebStrategy).secureCookie)
}

func TestHandleNewAuthorizationRequest(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		action         *policy.Action
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
	}{
		{ // Invalid Action Configuration
			generateAuthnzRequest("", "", "", "", ""),
			&policy.Action{},
			nil,
			"invalid OIDC configuration",
			int32(16),
			errors.New("invalid OIDC configuration"),
		},
		{ // New Authentication
			generateAuthnzRequest("", "", "", "", ""),
			&policy.Action{
				Client: fake.NewClient(),
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Body:    "",
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(), "https://tests.io/api/oidc/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
	}

	for _, test := range tests {
		t.Run("redirect uri test", func(t *testing.T) {
			api := WebStrategy{
				secureCookie: securecookie.New(securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)),
				tokenUtil:    MockValidator{},
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
					if !strings.HasPrefix(response.Headers["location"], test.directResponse.Headers["location"]) {
						assert.Fail(t, "incorrect location header")
					}
					assert.NotNil(t, test.directResponse.Headers["Set-Cookie"])
					assert.Equal(t, test.directResponse.Body, response.Body)
				}
			}
		})
	}
}

func TestErrCallback(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		action         *policy.Action
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
	}{
		{ // Err callback with cookies
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint, ""),
			&policy.Action{
				Client: &fake.Client{
					Server: &fake.AuthServer{Keys: &fake.KeySet{}},
				},
			},
			nil,
			"An err occurred",
			int32(16),
			nil,
		},
		{ // Err callback
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint, ""),
			&policy.Action{
				Client: &fake.Client{
					Server: &fake.AuthServer{Keys: &fake.KeySet{}},
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
			tokenUtil: MockValidator{},
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
		tokenResponse  *fake.TokenResponse
	}{
		{ // missing state
			generateAuthnzRequest("", "mycode", "", callbackEndpoint, ""),
			nil,
			"http: named cookie not present",
			int32(16),
			nil,
			&fake.TokenResponse{
				Err: errors.New("http: named cookie not present"),
			},
		},
		{ // missing state
			generateAuthnzRequest("", "mycode", "", callbackEndpoint, "hello"),
			nil,
			"http: named cookie not present",
			int32(16),
			nil,
			&fake.TokenResponse{
				Err: errors.New("http: named cookie not present"),
			},
		},
	}

	for _, test := range tests {
		// Test action
		action := &policy.Action{
			Client: &fake.Client{
				TokenResponse: test.tokenResponse,
				Server: &fake.AuthServer{
					Keys: &fake.KeySet{},
				},
			},
		}

		// Test strategy
		api := WebStrategy{
			tokenUtil: MockValidator{},
		}

		// Test
		r, err := api.HandleAuthnZRequest(test.req, action)
		if test.err != nil {
			assert.EqualError(t, err, test.err.Error())
		} else {
			assert.Equal(t, test.code, r.Result.Status.Code)
			assert.Equal(t, test.message, r.Result.Status.Message)
		}
	}
}

func generateAuthnzRequest(cookies string, code string, err string, path string, state string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Request: &authnz.RequestMsg{
				Scheme: "https",
				Host:   "tests.io",
				Path:   "/api" + path,
				Headers: &authnz.HeadersMsg{
					Cookies: cookies,
				},
				Params: &authnz.QueryParamsMsg{
					Code:  code,
					Error: err,
					State: state,
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

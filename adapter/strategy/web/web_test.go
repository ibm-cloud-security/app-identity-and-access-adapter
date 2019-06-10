package webstrategy

import (
	"errors"
	"github.com/gorilla/securecookie"
	"strings"
	"testing"

	"github.com/gogo/protobuf/types"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	err "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	authnz "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"github.com/stretchr/testify/assert"
	"istio.io/api/policy/v1beta1"
)

func TestNew(t *testing.T) {
	strategy := New(k8sfake.NewSimpleClientset())
	assert.NotNil(t, strategy)
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
			generateAuthnzRequest("", "", "", ""),
			&policy.Action{},
			nil,
			"invalid OIDC configuration",
			int32(16),
			errors.New("invalid OIDC configuration"),
		},
		{ // New Authentication
			generateAuthnzRequest("", "", "", ""),
			&policy.Action{
				Client: &fake.MockClient{
					Server: &fake.MockAuthServer{Keys: &fake.MockKeySet{}},
				},
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Body:    "",
				Headers: map[string]string{"location": "?client_id=id&redirect_uri=https%3A%2F%2Ftests.io%2Fapi%2Foidc%2Fcallback&response_type=code&scope=openid+profile+email"},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
	}

	for _, test := range tests {
		api := WebStrategy{
			secureCookie: securecookie.New(securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)),
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
				if !strings.HasPrefix(response.Headers["location"], test.directResponse.Headers["location"]) {
					println(test.directResponse.Headers["location"])
					println(response.Headers["location"])
					assert.Fail(t, "invalid redirect uri")
				}
				assert.NotNil(t, test.directResponse.Headers["Set-Cookie"])
				assert.Equal(t, test.directResponse.Body, response.Body)
			}
		}
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
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint),
			&policy.Action{
				Client: &fake.MockClient{
					Server: &fake.MockAuthServer{Keys: &fake.MockKeySet{}},
				},
			},
			nil,
			"An err occurred",
			int32(16),
			nil,
		},
		{ // Err callback
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint),
			&policy.Action{
				Client: &fake.MockClient{
					Server: &fake.MockAuthServer{Keys: &fake.MockKeySet{}},
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
		tokenResponse  *fake.TokenResponse
	}{
		{ // code callback without cookies
			generateAuthnzRequest("", "mycode", "", callbackEndpoint),
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
			Client: &fake.MockClient{
				TokenResponse: test.tokenResponse,
				Server: &fake.MockAuthServer{
					Keys: &fake.MockKeySet{},
				},
			},
		}

		// Test strategy
		api := WebStrategy{
			tokenUtil: MockValidator{
				err: nil,
			},
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

func generateAuthnzRequest(cookies string, code string, err string, path string) *authnz.HandleAuthnZRequest {
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

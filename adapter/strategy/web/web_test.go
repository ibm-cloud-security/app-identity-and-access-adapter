package webstrategy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/validator"

	"github.com/gogo/protobuf/types"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"istio.io/api/policy/v1beta1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/config"
	err "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/errors"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy/engine"
	authnz "github.com/ibm-cloud-security/app-identity-and-access-adapter/config/template"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/fake"
)

const (
	defaultHost        = "tests.io"
	defaultBasePath    = "/api"
	defaultState       = "session"
	defaultOriginalURL = "https://" + defaultHost + defaultBasePath
)

var defaultHashKey = securecookie.GenerateRandomKey(16)
var defaultBlockKey = securecookie.GenerateRandomKey(16)
var defaultSecureCookie = securecookie.New(defaultHashKey, defaultBlockKey)

func TestNew(t *testing.T) {
	strategy := New(&config.Config{}, k8sfake.NewSimpleClientset())
	assert.NotNil(t, strategy)
	assert.NotNil(t, strategy.(*WebStrategy).encrpytor)
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
			generateAuthnzRequest("", "", "", "", ""),
			&engine.Action{},
			nil,
			"invalid OIDC configuration",
			int32(16),
			errors.New("invalid OIDC configuration"),
		},
		{ // New Authentication
			generateAuthnzRequest("", "", "", "", ""),
			&engine.Action{
				Client: fake.NewClient(nil),
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://tests.io/api/oidc/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
		{ // New Authentication with a custom absolute-form callback URI
			generateAuthnzRequest("", "", "", "", ""),
			&engine.Action{
				Client: fake.NewClientWithCallback(nil, "/my/callback"),
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://tests.io/my/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
		{ // New Authentication with a custom relative-form callback URI
			generateAuthnzRequest("", "", "", "", ""),
			&engine.Action{
				Client: fake.NewClientWithCallback(nil, "my/callback"),
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://tests.io/api/my/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
		{ // New Authentication with a custom full callback URL
			generateAuthnzRequest("", "", "", "", ""),
			&engine.Action{
				Client: fake.NewClientWithCallback(nil, "https://my-adapter-domain.com/my/callback"),
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://my-adapter-domain.com/my/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
	}

	for _, test := range tests {
		t.Run("redirect uri test", func(t *testing.T) {
			api := WebStrategy{
				encrpytor: securecookie.New(securecookie.GenerateRandomKey(16), securecookie.GenerateRandomKey(16)),
				tokenUtil: MockValidator{},
			}
			r, errs := api.HandleAuthnZRequest(test.req, test.action)
			if test.err != nil {
				assert.EqualError(t, errs, test.err.Error())
			} else {
				assert.Equal(t, test.code, r.Result.Status.Code)
				assert.Equal(t, test.message, r.Result.Status.Message)
				compareDirectHttpResponses(t, r, test.directResponse)
			}
		})
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		action         *engine.Action
		sessionId      string
		session        *authserver.TokenResponse
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
	}{
		{ // successful refresh flow
			generateAuthnzRequest(createCookie().String(), "", "", "", ""),
			&engine.Action{
				Client: fake.NewClient(&fake.TokenResponse{
					Res: &authserver.TokenResponse{
						AccessToken:   "access",
						IdentityToken: "identity",
						RefreshToken:  "refresh",
						ExpiresIn:     10,
					},
				}),
			},
			defaultState,
			&authserver.TokenResponse{
				AccessToken:   "access",
				IdentityToken: "Token is expired",
				RefreshToken:  "refresh",
				ExpiresIn:     10,
			},
			nil,
			"User is authenticated",
			int32(0),
			nil,
		},
		{ // Refresh token request fails
			generateAuthnzRequest(createCookie().String(), "", "", "", ""),
			&engine.Action{
				Client: fake.NewClient(defaultFailureTokenResponse("could not retrieve tokens")),
			},
			defaultState,
			&authserver.TokenResponse{
				IdentityToken: "Token is expired",
				RefreshToken:  "refresh",
				ExpiresIn:     10,
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://tests.io/api/oidc/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
		{ // Refresh token is empty
			generateAuthnzRequest(createCookie().String(), "", "", "", ""),
			&engine.Action{
				Client: fake.NewClient(nil),
			},
			defaultState,
			&authserver.TokenResponse{
				IdentityToken: "Token is expired",
				ExpiresIn:     10,
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://tests.io/api/oidc/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
		{ // Refresh token request fails
			generateAuthnzRequest(createCookie().String(), "", "", "", ""),
			&engine.Action{
				Client: fake.NewClient(defaultFailureTokenResponse("could not retrieve tokens")),
			},
			defaultState,
			&authserver.TokenResponse{
				IdentityToken: "Token is expired",
				RefreshToken:  "refresh",
				ExpiresIn:     10,
			},
			&v1beta1.DirectHttpResponse{
				Code:    302,
				Headers: map[string]string{"location": generateAuthorizationURL(fake.NewClient(nil), "https://tests.io/api/oidc/callback", "")},
			},
			"Redirecting to identity provider",
			int32(16),
			nil,
		},
	}

	for _, ts := range tests {
		test := ts
		t.Run("refresh", func(t *testing.T) {
			t.Parallel()
			api := WebStrategy{
				ctx:        config.NewConfig(),
				tokenCache: new(sync.Map),
				encrpytor:  defaultSecureCookie,
				tokenUtil: MockValidator{
					validate: func(tkn string) *err.OAuthError {
						if !(tkn == "access" || tkn == "identity") {
							return &err.OAuthError{
								Msg: tkn,
							}
						}
						return nil
					},
				},
			}

			api.tokenCache.Store(test.sessionId, test.session)
			r, errs := api.HandleAuthnZRequest(test.req, test.action)
			if test.err != nil {
				assert.EqualError(t, errs, test.err.Error())
			} else {
				assert.Equal(t, test.code, r.Result.Status.Code)
				assert.Equal(t, test.message, r.Result.Status.Message)
				compareDirectHttpResponses(t, r, test.directResponse)
			}
		})
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
			generateAuthnzRequest("", "", "An err occurred", callbackEndpoint, ""),
			&engine.Action{
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
			&engine.Action{
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
	// Test strategy
	api := New(config.NewConfig(), k8sfake.NewSimpleClientset()).(*WebStrategy)
	api.encrpytor = defaultSecureCookie
	api.tokenUtil = MockValidator{
		func(s string) *err.OAuthError {
			if s == "invalid_token" {
				return &err.OAuthError{
					Code: err.InvalidToken,
				}
			}
			return nil
		},
	}

	encryptState := func(c *OidcState) string {
		state, err := api.encryptState(fake.NewClient(nil).ID(), c)
		if err != nil {
			panic(err)
		}
		return url.QueryEscape(state)
	}

	var tests = []struct {
		redirectUri    string
		tokenRes       *fake.TokenResponse
		req            *authnz.HandleAuthnZRequest
		directResponse *v1beta1.DirectHttpResponse
		message        string
		err            error
	}{
		{ // missing state
			"",
			nil,
			generateAuthnzRequest("", "code", "", callbackEndpoint, ""),
			&v1beta1.DirectHttpResponse{
				Code: 401,
			},
			"state parameter not provided",
			nil,
		},
		{ // bad state (unable to url-decode)
			"",
			nil,
			generateAuthnzRequest("", "code", "", callbackEndpoint, "inva%FFli%X0d-state"),
			&v1beta1.DirectHttpResponse{
				Code: 401,
			},
			"bad state parameter",
			nil,
		},
		{ // invalid state - not a properly encrypted state string
			"",
			nil,
			generateAuthnzRequest("", "code", "", callbackEndpoint, "invalidencryptedstate"),
			&v1beta1.DirectHttpResponse{
				Code: 401,
			},
			"invalid state parameter",
			nil,
		},
		{ // invalid state - expired (empty expiration date)
			"",
			nil,
			generateAuthnzRequest("", "code", "", callbackEndpoint, encryptState(&OidcState{})),
			&v1beta1.DirectHttpResponse{
				Code: 401,
			},
			"invalid state parameter",
			nil,
		},
		{ // could not exchange grant code
			"",
			defaultFailureTokenResponse("problem getting tokens"),
			generateAuthnzRequest("", "code", "", callbackEndpoint, encryptState(&OidcState{Expiration: time.Now().Add(1 * time.Minute)})),
			&v1beta1.DirectHttpResponse{
				Code: 401,
			},
			"problem getting tokens",
			nil,
		},
		{ // invalid tokens
			"",
			&fake.TokenResponse{
				Res: &authserver.TokenResponse{
					IdentityToken: "invalid_token",
				},
			},
			generateAuthnzRequest("", "code", "", callbackEndpoint, encryptState(&OidcState{Expiration: time.Now().Add(1 * time.Minute)})),
			&v1beta1.DirectHttpResponse{
				Code: 401,
			},
			"invalid_token",
			nil,
		},
		{ // success
			"",
			defaultSuccessTokenResponse(),
			generateAuthnzRequest("", "code", "", callbackEndpoint, encryptState(&OidcState{Expiration: time.Now().Add(1 * time.Minute), OriginalURL: defaultOriginalURL})),
			&v1beta1.DirectHttpResponse{
				Code: 302,
				Headers: map[string]string{
					"location": defaultOriginalURL,
					setCookie:  "oidc-test-id",
				},
			},
			"Successfully authenticated : redirecting to original URL",
			nil,
		},
		{ // success w/new redirect
			"https://" + defaultHost + "/another_path",
			defaultSuccessTokenResponse(),
			generateAuthnzRequest("", "code", "", callbackEndpoint, encryptState(&OidcState{Expiration: time.Now().Add(1 * time.Minute)})),
			&v1beta1.DirectHttpResponse{
				Code: 302,
				Headers: map[string]string{
					"location": "https://" + defaultHost + "/another_path",
					setCookie:  "oidc-test-id",
				},
			},
			"Successfully authenticated : redirecting to original URL",
			nil,
		},
	}

	for _, ts := range tests {
		test := ts
		t.Run("callback", func(t *testing.T) {
			t.Parallel()
			action := &engine.Action{}
			action.Client = fake.NewClient(test.tokenRes)
			action.RedirectUri = test.redirectUri

			r, errs := api.HandleAuthnZRequest(test.req, action)
			if test.err != nil {
				assert.EqualError(t, errs, test.err.Error())
			} else {
				assert.Equal(t, int32(16), r.Result.Status.Code)
				assert.Equal(t, test.message, r.Result.Status.Message)
				compareDirectHttpResponses(t, r, test.directResponse)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	var tests = []struct {
		req            *authnz.HandleAuthnZRequest
		directResponse *v1beta1.DirectHttpResponse
		message        string
		code           int32
		err            error
		tokenResponse  *fake.TokenResponse
	}{
		{
			generateAuthnzRequest("", "", "", "/oidc/logout", ""),
			nil,
			"Successfully authenticated : redirecting to original URL",
			int32(16),
			nil,
			&fake.TokenResponse{},
		},
	}

	for _, test := range tests {
		action := &engine.Action{
			Client: fake.NewClient(test.tokenResponse),
		}

		api := WebStrategy{
			ctx:       config.NewConfig(),
			tokenUtil: MockValidator{},
		}

		r, errs := api.HandleAuthnZRequest(test.req, action)
		if test.err != nil {
			assert.EqualError(t, errs, test.err.Error())
		} else {
			assert.Equal(t, test.code, r.Result.Status.Code)
			assert.Equal(t, test.message, r.Result.Status.Message)
		}
	}
}

func compareDirectHttpResponses(t *testing.T, r *authnz.HandleAuthnZResponse, expected *v1beta1.DirectHttpResponse) {
	if expected == nil {
		return
	}
	response := &v1beta1.DirectHttpResponse{}
	for _, detail := range r.Result.Status.Details {
		if types.UnmarshalAny(detail, response) != nil {
			continue
		}
		assert.Equal(t, expected.Code, response.Code)
		for expectKey, expectValue := range expected.Headers {
			if expectKey == setCookie {
				assert.NotEmpty(t, response.Headers[setCookie])
				continue
			}
			if !strings.HasPrefix(response.Headers[expectKey], expectValue) {
				assert.Fail(t, "incorrect header value: '"+expectKey+
					"'\n found: "+response.Headers[expectKey]+
					"\n expected: "+expectValue)
			}
		}

		assert.Equal(t, expected.Body, response.Body)
	}
}

func defaultSessionOidcCookie() *OidcState {
	return &OidcState{
		OriginalURL: defaultOriginalURL,
		Expiration:  time.Now().Add(time.Hour),
	}
}

func defaultSuccessTokenResponse() *fake.TokenResponse {
	return &fake.TokenResponse{
		Res: &authserver.TokenResponse{
			IdentityToken: "identity",
		},
	}
}

func defaultFailureTokenResponse(msg string) *fake.TokenResponse {
	return &fake.TokenResponse{
		Err: errors.New(msg),
	}
}

func generateAuthnzRequest(cookies string, code string, err string, path string, state string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Request: &authnz.RequestMsg{
				Scheme: "https",
				Host:   defaultHost,
				Path:   defaultBasePath + path,
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
				Path:      defaultBasePath + path,
				Method:    "GET",
			},
		},
	}
}

type MockValidator struct {
	validate func(string) *err.OAuthError
}

func (v MockValidator) Validate(tkn string, tokenType validator.Token, ks keyset.KeySet, rules []v1.Rule, userInfoEndpoint string) *err.OAuthError {
	if v.validate == nil {
		return nil
	}
	return v.validate(tkn)
}

func createCookie() *http.Cookie {
	return &http.Cookie{
		Name:     "oidc-cookie-id",
		Value:    defaultState,
		Path:     "/",
		Secure:   false, // disabled for tests
		HttpOnly: true,  // Cookie available to HTTP protocol only (no JS access)
		//TODO: possible to use Expires instead of Max-Age once Istio supports it,
		// see https://github.com/istio/istio/pull/21270
		//Expires:  time.Now().Add(time.Hour * time.Duration(2160)), // 90 days
		MaxAge: 90 * 24 * 60 * 60, // 90 days
	}
}

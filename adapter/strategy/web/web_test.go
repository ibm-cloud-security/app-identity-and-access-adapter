package webstrategy

import (
	"errors"
	"testing"

	err "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/validator"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	strategy := New()
	assert.NotNil(t, strategy)
}

func TestHandleNewAuthorizationRequest(t *testing.T) {
	var tests = []struct {
		req      *authnz.HandleAuthnZRequest
		policies []engine.PolicyAction
		message  string
		code     int32
		err      error
	}{
		{
			generateAuthnzRequest("", "", "", "", "", ""),
			make([]engine.PolicyAction, 0),
			"invalid OIDC strategy configuration",
			int32(16),
			errors.New("invalid OIDC strategy configuration"),
		},
	}

	for _, test := range tests {
		api := WebStrategy{
			tokenUtil: MockValidator{
				err: nil,
			},
		}
		_, err := api.HandleAuthnZRequest(test.req, test.policies)
		assert.EqualError(t, err, test.err.Error())
	}
}

func generateAuthnzRequest(cookie string, code string, error string, scheme string, host string, path string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Request: &authnz.RequestMsg{
				Scheme: scheme,
				Host:   host,
				Path:   path,
				Headers: &authnz.HeadersMsg{
					Cookies: cookie,
				},
				Params: &authnz.QueryParamsMsg{
					Code:  code,
					Error: error,
				},
			},
		},
	}
}

type MockValidator struct {
	err *err.OAuthError
}

func (v MockValidator) Validate(tokens validator.RawTokens, policies []engine.PolicyAction) *err.OAuthError {
	return v.err
}

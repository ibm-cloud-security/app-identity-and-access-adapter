package webstrategy

import (
	"ibmcloudappid/adapter/errors"
	"ibmcloudappid/adapter/policy/engine"
	"ibmcloudappid/adapter/validator"
	"ibmcloudappid/config/template"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	strategy := New()
	assert.NotNil(t, strategy)
}

func TestHandleNewAuthorizationRequest(t *testing.T) {
	var tests = []struct {
		req           *authnz.HandleAuthnZRequest
		policies      []engine.PolicyAction
		message       string
		code          int32
		validationErr *errors.OAuthError
	}{
		{
			generateAuthnzRequest("", "", "", "", "", ""),
			make([]engine.PolicyAction, 0),
			"authorization header not provided",
			int32(16),
			nil,
		},
		{
			generateAuthnzRequest("", "", "", "", "", ""),
			make([]engine.PolicyAction, 0),
			"authorization header malformed - expected 'Bearer <access_token> <optional id_token>'",
			int32(16),
			nil,
		},
	}

	for _, test := range tests {
		api := WebStrategy{
			tokenUtil: MockValidator{
				err: test.validationErr,
			},
		}
		checkresult, err := api.HandleAuthnZRequest(test.req, test.policies)
		assert.Nil(t, err)
		assert.Equal(t, test.message, checkresult.Result.Status.Message)
		assert.Equal(t, test.code, checkresult.Result.Status.Code)
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
	err *errors.OAuthError
}

func (v MockValidator) Validate(tokens validator.RawTokens, policies []engine.PolicyAction) *errors.OAuthError {
	return v.err
}

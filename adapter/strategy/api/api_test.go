package apistrategy

import (
	"testing"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/stretchr/testify/assert"
	"ibmcloudappid/adapter/errors"
	"ibmcloudappid/adapter/policy/manager"
	"ibmcloudappid/adapter/validator"
	"istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/template/authorization"
)

func TestNew(t *testing.T) {
	strategy := New()
	assert.NotNil(t, strategy)
}

func TestHandleAuthorizationRequest(t *testing.T) {
	var tests = []struct {
		req           *authorization.HandleAuthorizationRequest
		policies      []manager.PolicyAction
		message       string
		code          int32
		validationErr *errors.OAuthError
	}{
		{
			generateAuthRequest(""),
			make([]manager.PolicyAction, 0),
			"authorization header not provided",
			int32(16),
			nil,
		},
		{
			generateAuthRequest("bearer"),
			make([]manager.PolicyAction, 0),
			"authorization header malformed - expected 'Bearer <access_token> <optional id_token>'",
			int32(16),
			nil,
		},
		{
			generateAuthRequest("Bearer invalid"),
			make([]manager.PolicyAction, 0),
			"invalid token",
			int32(16),
			errors.UnauthorizedHTTPException("invalid token", nil),
		},
		{
			generateAuthRequest("Bearer access"),
			make([]manager.PolicyAction, 0),
			"",
			int32(0),
			nil,
		},
		{
			generateAuthRequest("Bearer access id"),
			make([]manager.PolicyAction, 0),
			"",
			int32(0),
			nil,
		},
	}

	for _, test := range tests {
		api := APIStrategy{
			tokenUtil: MockValidator{
				err: test.validationErr,
			},
		}
		checkresult, err := api.HandleAuthorizationRequest(test.req, test.policies)
		assert.Nil(t, err)
		assert.Equal(t, test.message, checkresult.Status.Message)
		assert.Equal(t, test.code, checkresult.Status.Code)
	}
}

func TestParseRequest(t *testing.T) {
	var tests = []struct {
		props       map[string]interface{}
		expectErr   bool
		expectedMsg string
	}{
		{
			map[string]interface{}{"dummy": "value"},
			true,
			"authorization header not provided",
		},
		{
			map[string]interface{}{"authorization_header": ""},
			true,
			"authorization header not provided",
		},
		{
			map[string]interface{}{"authorization_header": "bearer"},
			true,
			"authorization header malformed - expected 'Bearer <access_token> <optional id_token>'",
		},
		{
			map[string]interface{}{"authorization_header": "b access id"},
			true,
			"unsupported authorization header format - expected 'Bearer <access_token> <optional id_token>'",
		},
		{
			map[string]interface{}{"authorization_header": "Bearer access id"},
			false,
			"",
		},
		{
			map[string]interface{}{"authorization_header": "bearer access id"},
			false,
			"",
		},
	}

	for _, e := range tests {
		tokens, err := getAuthTokensFromRequest(e.props)
		if !e.expectErr && tokens != nil {
			assert.Equal(t, "access", tokens.Access)
			assert.Equal(t, "id", tokens.ID)
		} else {
			assert.EqualError(t, err, e.expectedMsg)
		}

	}
}

func TestErrorResponse(t *testing.T) {
	var tests = []struct {
		err          *errors.OAuthError
		Message      string
		ResponseCode v1beta1.HttpStatusCode
		Body         string
		HeadersMap   map[string]string
	}{
		{
			err: &errors.OAuthError{
				Msg:    "missing header",
				Code:   errors.InvalidToken,
				Scopes: []string{"scope"},
			},
			Message:      "missing header",
			ResponseCode: v1beta1.Unauthorized,
			Body:         errors.InvalidToken,
			HeadersMap:   make(map[string]string, 0),
		},
	}
	for _, test := range tests {
		checkresult := buildErrorResponse(test.err)
		assert.Equal(t, checkresult.Status.Code, int32(rpc.UNAUTHENTICATED))
		assert.Equal(t, checkresult.Status.Message, test.Message)
		assert.NotNil(t, checkresult.Status.Details)
	}
}

func generateAuthRequest(header string) *authorization.HandleAuthorizationRequest {
	return &authorization.HandleAuthorizationRequest{
		Instance: &authorization.InstanceMsg{
			Name: "",
			Subject: &authorization.SubjectMsg{
				Properties: map[string]*v1beta1.Value{
					"authorization_header": &v1beta1.Value{
						Value: &v1beta1.Value_StringValue{
							StringValue: header,
						},
					},
				},
			},
			Action: nil,
		},
	}
}

type MockValidator struct {
	err *errors.OAuthError
}

func (v MockValidator) Validate(tokens validator.RawTokens, policies []manager.PolicyAction) *errors.OAuthError {
	return v.err
}

package apistrategy

import (
	"ibmcloudappid/config/template"
	"testing"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/stretchr/testify/assert"
	"ibmcloudappid/adapter/errors"
	"ibmcloudappid/adapter/policy/engine"
	"ibmcloudappid/adapter/validator"
	"istio.io/api/policy/v1beta1"
)

func TestNew(t *testing.T) {
	strategy := New()
	assert.NotNil(t, strategy)
}

func TestHandleAuthorizationRequest(t *testing.T) {
	var tests = []struct {
		req           *authnz.HandleAuthnZRequest
		policies      []engine.PolicyAction
		message       string
		code          int32
		validationErr *errors.OAuthError
	}{
		{
			generateAuthRequest(""),
			make([]engine.PolicyAction, 0),
			"authorization header not provided",
			int32(16),
			nil,
		},
		{
			generateAuthRequest("bearer"),
			make([]engine.PolicyAction, 0),
			"authorization header malformed - expected 'Bearer <access_token> <optional id_token>'",
			int32(16),
			nil,
		},
		{
			generateAuthRequest("Bearer invalid"),
			make([]engine.PolicyAction, 0),
			"invalid token",
			int32(16),
			errors.UnauthorizedHTTPException("invalid token", nil),
		},
		{
			generateAuthRequest("Bearer access"),
			make([]engine.PolicyAction, 0),
			"",
			int32(0),
			nil,
		},
		{
			generateAuthRequest("Bearer access id"),
			make([]engine.PolicyAction, 0),
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
		checkresult, err := api.HandleAuthnZRequest(test.req, test.policies)
		assert.Nil(t, err)
		assert.Equal(t, test.message, checkresult.Result.Status.Message)
		assert.Equal(t, test.code, checkresult.Result.Status.Code)
	}
}

func TestParseRequest(t *testing.T) {
	var tests = []struct {
		r           *authnz.HandleAuthnZRequest
		expectErr   bool
		expectedMsg string
	}{
		{
			&authnz.HandleAuthnZRequest{
				Instance: &authnz.InstanceMsg{
					Name:    "",
					Subject: &authnz.SubjectMsg{Credentials: &authnz.CredentialsMsg{}},
				},
			},
			true,
			"authorization header not provided",
		},
		{
			generateAuthRequest(""),
			true,
			"authorization header not provided",
		},
		{
			generateAuthRequest("bearer"),
			true,
			"authorization header malformed - expected 'Bearer <access_token> <optional id_token>'",
		},
		{
			generateAuthRequest("b access id"),
			true,
			"unsupported authorization header format - expected 'Bearer <access_token> <optional id_token>'",
		},
		{
			generateAuthRequest("Bearer access id"),
			false,
			"",
		},
		{
			generateAuthRequest("bearer access id"),
			false,
			"",
		},
	}

	for _, e := range tests {
		tokens, err := getAuthTokensFromRequest(e.r)
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
		assert.Equal(t, checkresult.Result.Status.Code, int32(rpc.UNAUTHENTICATED))
		assert.Equal(t, checkresult.Result.Status.Message, test.Message)
		assert.NotNil(t, checkresult.Result.Status.Details)
	}
}

func generateAuthRequest(header string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Name: "",
			Subject: &authnz.SubjectMsg{
				Credentials: &authnz.CredentialsMsg{
					AuthorizationHeader: header,
				},
			},
			Action: nil,
		},
	}
}

type MockValidator struct {
	err *errors.OAuthError
}

func (v MockValidator) Validate(tokens validator.RawTokens, policies []engine.PolicyAction) *errors.OAuthError {
	return v.err
}

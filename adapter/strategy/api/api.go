package apistrategy

import (
	"strings"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"ibmcloudappid/adapter/errors"
	"ibmcloudappid/adapter/policy/engine"
	"ibmcloudappid/adapter/strategy"
	"ibmcloudappid/adapter/validator"
	adapter "istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

const (
	authorizationHeader = "authorization_header"
	bearer              = "Bearer"
	wwwAuthenticate     = "WWW-Authenticate"
)

// APIStrategy handles authorization requests
type APIStrategy struct {
	tokenUtil validator.TokenValidator
}

////////////////// constructor //////////////////

// New constructs a new APIStrategy used to handle API Requests
func New() strategy.Strategy {
	return &APIStrategy{
		tokenUtil: validator.New(),
	}
}

////////////////// interface methods //////////////////

// HandleAuthorizationRequest parses and validates requests using the API Strategy
func (s *APIStrategy) HandleAuthorizationRequest(r *authorization.HandleAuthorizationRequest, policies []engine.PolicyAction) (*adapter.CheckResult, error) {
	props := strategy.DecodeValueMap(r.Instance.Subject.Properties)

	// Parse Authorization Header
	tokens, err := getAuthTokensFromRequest(props)
	if err != nil {
		log.Debugf("Unauthorized: " + err.Error())
		return buildErrorResponse(err), nil
	}

	// Validate Authorization Tokens
	err = s.tokenUtil.Validate(*tokens, policies)
	if err != nil {
		log.Debugf("Unauthorized: " + err.Error())
		return buildErrorResponse(err), nil
	}

	log.Debug("Found valid authorization header")

	return &adapter.CheckResult{Status: status.OK}, nil
}

////////////////// utilities //////////////////

// Parse authorization header from gRPC props
func getAuthTokensFromRequest(props map[string]interface{}) (*validator.RawTokens, *errors.OAuthError) {

	if v, found := props[authorizationHeader]; found {

		if authHeader, ok := v.(string); ok {

			// Authorization header should exist
			if authHeader == "" {
				return nil, errors.UnauthorizedHTTPException("authorization header not provided", nil)
			}

			// Authorization header must be in the format Bearer <access_token> <optional id_token>
			parts := strings.SplitN(authHeader, " ", 3)
			if len(parts) != 2 && len(parts) != 3 {
				return nil, errors.UnauthorizedHTTPException("authorization header malformed - expected 'Bearer <access_token> <optional id_token>'", nil)
			}

			// Authorization header must begin with bearer
			if parts[0] != "Bearer" && parts[0] != "bearer" {
				return nil, errors.UnauthorizedHTTPException("unsupported authorization header format - expected 'Bearer <access_token> <optional id_token>'", nil)
			}

			var idToken = ""
			if len(parts) == 3 {
				idToken = parts[2]
			}

			return &validator.RawTokens{
				Access: parts[1],
				ID:     idToken,
			}, nil
		}
	}
	return nil, errors.UnauthorizedHTTPException("authorization header not provided", nil)
}

// buildErrorResponse creates the rfc specified OAuth 2.0 error result
func buildErrorResponse(err *errors.OAuthError) *adapter.CheckResult {
	header := bearer + " realm=\"token\""
	if err != nil {
		scopes := err.ScopeStr()
		if scopes != "" {
			header += ", scopes=\"" + scopes + "\""
		}
		if err.Code != "" {
			header += ", error=\"" + err.Code + "\""
		}
		if err.Msg != "" {
			header += ", error_description=\"" + err.Msg + "\""
		}
	}
	return &adapter.CheckResult{
		Status: rpc.Status{
			Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
			Message: err.Error(),
			Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
				Code:    err.HTTPCode(), // Response Mixer remaps on request
				Body:    err.ShortDescription(),
				Headers: map[string]string{wwwAuthenticate: header},
			})},
		},
	}
}
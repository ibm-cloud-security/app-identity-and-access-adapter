package apistrategy

import (
	"strings"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/strategy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/validator"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	adapter "istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/pkg/log"
)

const (
	bearer          = "Bearer"
	wwwAuthenticate = "WWW-Authenticate"
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
func (s *APIStrategy) HandleAuthnZRequest(r *authnz.HandleAuthnZRequest, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {

	// Parse Authorization Header
	tokens, err := getAuthTokensFromRequest(r)
	if err != nil {
		log.Debugf("Unauthorized: " + err.Error())
		return buildErrorResponse(err), nil
	}

	// Validate Access Token
	err = s.tokenUtil.Validate(tokens.Access, action.KeySet, action.Rules)
	if err != nil {
		log.Debugf("Invalid access token: " + err.Error())
		return buildErrorResponse(err), nil
	}

	// Validate ID Token
	if tokens.ID != "" {
		err = s.tokenUtil.Validate(tokens.ID, action.KeySet, action.Rules)
		if err != nil {
			log.Debugf("Invalid ID token: " + err.Error())
			return buildErrorResponse(err), nil
		}
	}

	log.Debug("Found valid authorization header")

	return &authnz.HandleAuthnZResponse{
		Result: &adapter.CheckResult{Status: status.OK},
	}, nil
}

////////////////// utilities //////////////////

// Parse authorization header from gRPC props
func getAuthTokensFromRequest(r *authnz.HandleAuthnZRequest) (*validator.RawTokens, *errors.OAuthError) {
	authHeader := r.Instance.Request.Headers.Authorization

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

// buildErrorResponse creates the rfc specified OAuth 2.0 error result
func buildErrorResponse(err *errors.OAuthError) *authnz.HandleAuthnZResponse {
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
	return &authnz.HandleAuthnZResponse{
		Result: &adapter.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: err.Error(),
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code:    err.HTTPCode(), // Response Mixer remaps on request
					Body:    err.ShortDescription(),
					Headers: map[string]string{wwwAuthenticate: header},
				})},
			},
		},
	}

}

package apistrategy

import (
	"fmt"
	"strings"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"ibmcloudappid/errors"
	"ibmcloudappid/policy/manager"
	"ibmcloudappid/validator"
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

type tokens struct {
	access string
	id     string
}

// APIStrategy handles authorization requests
type APIStrategy struct {
	parser validator.TokenValidator
}

// New constructs a new APIStrategy used to handle API Requests
func New() *APIStrategy {
	return &APIStrategy{
		parser: validator.New(),
	}
}

// HandleAuthorizationRequest parses and validates requests using the API Strategy
func (s *APIStrategy) HandleAuthorizationRequest(r *authorization.HandleAuthorizationRequest, policies []manager.PolicyAction) (*adapter.CheckResult, error) {
	props := decodeValueMap(r.Instance.Subject.Properties)

	// Parse Authorization Header
	tokens, err := getAuthTokensFromRequest(props)
	if err != nil {
		log.Debugf("Unauthorized: " + err.Error())
		return buildErrorResponse(err)
	}

	log.Debug("Found valid authorization header")

	seen := make(map[string]bool)

	for _, p := range policies {

		if wasSeen, ok := seen[p.KeySet.PublicKeyURL()]; ok && !wasSeen {

			seen[p.KeySet.PublicKeyURL()] = true
		}

		// Validate access token
		err = s.parser.Validate(tokens.access, p.KeySet)
		if err != nil {
			log.Debugf("Unauthorized - invalid access token - %s", err)
			return buildErrorResponse(err)
		}

		// If necessary, validate ID token
		if tokens.id != "" {
			err = s.parser.Validate(tokens.id, p.KeySet)
			if err != nil {
				log.Debugf("Unauthorized - invalid ID token - %s", err)
				return buildErrorResponse(err)
			}
		}

		log.Debug("Authorized. Received valid authorization header.")
	}

	return &adapter.CheckResult{Status: status.OK}, nil
}

// Parse authorization header from gRPC props
func getAuthTokensFromRequest(props map[string]interface{}) (*tokens, *errors.OAuthError) {

	if v, found := props[authorizationHeader]; found {

		if authHeader, ok := v.(string); ok {

			// Authorization header should exist
			if authHeader == "" {
				return nil, errors.NewInvalidRequestError("missing authorization header")

			}

			// Authorization header must be in the format Bearer <access_token> <optional id_token>
			parts := strings.SplitN(authHeader, " ", 3)
			if len(parts) != 2 && len(parts) != 3 {
				return nil, errors.NewInvalidRequestError("authorization header malformed - expected 'Bearer <access_token> <optional id_token>'")
			}

			// Authorization header must begin with bearer
			if parts[0] != "Bearer" && parts[0] != "bearer" {
				return nil, errors.NewInvalidRequestError("invalid authorization header format - expected 'bearer'")
			}

			var idToken = ""
			if len(parts) == 3 {
				idToken = parts[2]
			}

			return &tokens{
				access: parts[1],
				id:     idToken,
			}, nil
		}
	}
	return nil, errors.NewInvalidRequestError("authorization header does not exist")
}

//// SHARED TODO MOVE ////

// Decodes gRPC values into string interface
func decodeValueMap(in map[string]*policy.Value) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = decodeValue(v.GetValue())
	}
	return out
}

// Decodes policy value into standard type
func decodeValue(in interface{}) interface{} {
	switch t := in.(type) {
	case *policy.Value_StringValue:
		return t.StringValue
	case *policy.Value_Int64Value:
		return t.Int64Value
	case *policy.Value_DoubleValue:
		return t.DoubleValue
	case *policy.Value_IpAddressValue:
		return t.IpAddressValue
	default:
		return fmt.Sprintf("%v", in)
	}
}

// buildErrorResponse creates the rfc specified OAuth 2.0 error result
func buildErrorResponse(err *errors.OAuthError) (*adapter.CheckResult, error) {
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
	}, nil
}

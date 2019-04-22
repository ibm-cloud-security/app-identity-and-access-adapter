package apistrategy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gogo/googleapis/google/rpc"
	adapter "istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/adapter/ibmcloudappid/keyutil"
	"istio.io/istio/mixer/adapter/ibmcloudappid/monitor"
	"istio.io/istio/mixer/adapter/ibmcloudappid/validator"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

const (
	authorizationHeader = "authorization_header"
)

type tokens struct {
	access string
	id     string
}

// APIStrategy handles authorization requests
type APIStrategy struct {
	parser  validator.TokenValidator
	keyUtil keyutil.KeyUtil
	cfg     monitor.AppIDConfig
}

// Options contains config info for ap strategy
type Options struct {
}

// New constructs a new APIStrategy used to handle API Requests
func New(cfg monitor.AppIDConfig, parser validator.TokenValidator, keyUtil keyutil.KeyUtil) (*APIStrategy, error) {
	return &APIStrategy{
		parser:  parser,
		keyUtil: keyUtil,
		cfg:     cfg,
	}, nil
}

// HandleAuthorizationRequest parses and validates requests using the API Strategy
func (s *APIStrategy) HandleAuthorizationRequest(r *authorization.HandleAuthorizationRequest) (*adapter.CheckResult, error) {
	props := decodeValueMap(r.Instance.Subject.Properties)

	// Parse Authorization Header
	tokens, err := getAuthTokensFromRequest(props)
	if err != nil {
		log.Debug("Unauthorized - authorization header was not found.")
		return &adapter.CheckResult{
			Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized - authorization header was not found."),
		}, nil
	}

	log.Debug("Found valid authorization header")

	// Validate access token
	err = s.parser.Validate(s.keyUtil.PublicKeys(), tokens.access, s.cfg.ClientCredentials.TenantID)
	if err != nil {
		log.Debugf("Unauthorized - invalid access token - %s", err)
		return &adapter.CheckResult{
			Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized - invalid access token."),
		}, nil
	}

	// If necessary, validate ID token
	if tokens.id != "" {
		err = s.parser.Validate(s.keyUtil.PublicKeys(), tokens.id, s.cfg.ClientCredentials.TenantID)
		if err != nil {
			log.Debugf("Unauthorized - invalid ID token - %s", err)
			return &adapter.CheckResult{
				Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized - invalid ID token."),
			}, nil
		}
	}

	log.Debug("Authorized. Received valid authorization header.")

	return &adapter.CheckResult{Status: status.OK}, nil
}

// Parse authorization header from gRPC props
func getAuthTokensFromRequest(props map[string]interface{}) (*tokens, error) {

	if v, found := props[authorizationHeader]; found {

		if authHeader, ok := v.(string); ok {

			// Authorization header should exist
			if authHeader == "" {
				return nil, errors.New("missing authorization header")
			}

			// Authorization header must be in the format Bearer <access_token> <optional id_token>
			parts := strings.SplitN(authHeader, " ", 3)
			if len(parts) != 2 && len(parts) != 3 {
				return nil, errors.New("authorization header malformed - expected 'Bearer <access_token> <optional id_token>'")
			}

			// Authorization header must begin with bearer
			if parts[0] != "Bearer" && parts[0] != "bearer" {
				return nil, errors.New("invalid authorization header format - expected 'bearer'")
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

	return nil, errors.New("authorization header does not exist")
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
package ibmcloudappid

import (
	"errors"
	"strings"

	"github.com/gogo/googleapis/google/rpc"

	"istio.io/api/mixer/adapter/model/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

type tokens struct {
	access string
	id     string
}

func (s *AppidAdapter) appIDAPIStrategy(r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	props := decodeValueMap(r.Instance.Subject.Properties)

	// Parse Authorization Header
	tokens, err := getAuthTokensFromRequest(props)
	if err != nil {
		log.Warn("Unauthorized. Authorization header not found.")
		return &v1beta1.CheckResult{
			Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized. Authorization header not found."),
		}, nil
	}

	log.Debug("Found valid authorization header")

	// Validate access token
	err = s.parser.Validate(s.keyUtil.GetPublicKeys(), tokens.access, s.cfg.ClientCredentials.TenantID)
	if err != nil {
		return &v1beta1.CheckResult{
			Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized. Invalid access token."),
		}, nil
	}

	// If necessary, validate ID token
	if tokens.id != "" {
		err = s.parser.Validate(s.keyUtil.GetPublicKeys(), tokens.id, s.cfg.ClientCredentials.TenantID)
		if err != nil {
			return &v1beta1.CheckResult{
				Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized. Invalid id token."),
			}, nil
		}
	}

	log.Info("Authorized. Valid authorization header")

	return &v1beta1.CheckResult{Status: status.OK}, nil
}

func getAuthTokensFromRequest(props map[string]interface{}) (*tokens, error) {

	if v, found := props[authorizationHeader]; found {

		if authHeader, ok := v.(string); ok {

			// Authorization header should exist
			if authHeader == "" {
				return nil, errors.New("Empty authorization header")
			}

			// Authorization header must be in the format Bearer <access_token> <optional id_token>
			parts := strings.SplitN(authHeader, " ", 3)
			if len(parts) != 2 && len(parts) != 3 {
				return nil, errors.New("Authorization header malformed")
			}

			// Authorization header must begin with bearer
			if parts[0] != "Bearer" && parts[0] != "bearer" {
				return nil, errors.New("Invalid bearer header")
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

	return nil, errors.New("Authorizaiton header does not exist")
}

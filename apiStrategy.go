package ibmcloudappid

import (
	"errors"
	"github.com/gogo/googleapis/google/rpc"
	"strings"

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
			Status: status.WithPermissionDenied("Unauthorized. Authorization header not found."),
		}, nil
	}

	log.Debug("Found valid authorization header")

	// Validate access token
	err = s.parser.Validate(s.keyUtil.GetPublicKeys(), tokens.access, s.cfg.TenantID)
	if err != nil {
		return &v1beta1.CheckResult{
			Status: status.WithPermissionDenied("Unauthorized. Invalid access token."),
		}, nil
	}

	// If necessary, validate ID token
	if tokens.id != "" {
		err = s.parser.Validate(s.keyUtil.GetPublicKeys(), tokens.id, s.cfg.TenantID)
		if err != nil {
			return &v1beta1.CheckResult{
				Status: status.WithMessage(rpc.UNAUTHENTICATED, "Unauthorized. Invalid id token."),
				//Status: status.WithPermissionDenied("Unauthorized. Invalid id token."),
			}, nil
		}
	}

	return &v1beta1.CheckResult{Status: status.OK}, nil
}

func getAuthTokensFromRequest(props map[string]interface{}) (*tokens, error) {

	for k, v := range props {
		log.Infof(">> HandleAuthorization :: Received properties: key=%s value=%s", k, v)
		if k == authorizationHeader {

			// Authorization header should exist
			if v == "" {
				return nil, errors.New("Empty authorization header")
			}

			// Authorization header must be in the format Bearer <access_token> <optional id_token>
			parts := strings.SplitN(v.(string), " ", 3)
			if len(parts) != 2 && len(parts) != 3 {
				return nil, errors.New("Authorization header malformed")
			}

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

package ibmcloudappid

import (
	"errors"
	"strings"

	"istio.io/api/mixer/adapter/model/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

func (s *AppidAdapter) appIDAPIStrategy(r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	props := decodeValueMap(r.Instance.Subject.Properties)

	accessToken, err := getAuthTokenFromRequest(props)
	if err != nil {
		log.Infof("Authentication Failure; Authorization header not provided")
		return &v1beta1.CheckResult{
			Status: status.WithPermissionDenied("Unauthorized..."),
		}, nil
	}

	log.Infof("Found the authorization header with access token: %s", accessToken)

	token, err := s.cfg.Parser.Validate(s.appIDPubkeys, accessToken, s.cfg.TenantID)
	if err != nil {
		return &v1beta1.CheckResult{
			Status: status.WithPermissionDenied("Invalid access token"),
		}, nil
	}

	log.Infof("Valid raw access token: %s", token.Raw)
	return &v1beta1.CheckResult{Status: status.OK}, nil
}

func getAuthTokenFromRequest(props map[string]interface{}) (string, error) {

	for k, v := range props {
		log.Infof(">> HandleAuthorization :: Received properties: key=%s value=%s", k, v)
		if k == authorizationHeader {

			if v == "" {
				return "", errors.New("Empty authorization header")
			}

			parts := strings.SplitN(v.(string), " ", 3)
			if len(parts) != 2 && len(parts) != 3 {
				return "", errors.New("Authorization header malformed")
			}

			if parts[0] != "Bearer" && parts[0] != "bearer" {
				return "", errors.New("Invalid bearer header")
			}

			return parts[1], nil
		}
	}

	return "", errors.New("No authorizaiton header found")
}

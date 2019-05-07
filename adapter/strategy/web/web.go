package webstrategy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"github.com/gorilla/securecookie"
	"gopkg.in/mgo.v2/bson"
	"ibmcloudappid/adapter/client"
	"ibmcloudappid/adapter/policy/engine"
	"ibmcloudappid/adapter/strategy"
	"ibmcloudappid/adapter/validator"
	"ibmcloudappid/config/template"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/pkg/log"
)

const (
	oauthQueryError   = "error"
	authorizationCode = "authorization_code"
	location          = "location"
	setCookie         = "Set-Cookie"
	adapterCookie     = "ISTIO-ADAPTER"
)

var hashKey = securecookie.GenerateRandomKey(32)
var blockKey = securecookie.GenerateRandomKey(16)
var secretCookie = securecookie.New(hashKey, blockKey)

// WebStrategy handles OAuth 2.0 / OIDC flows
type WebStrategy struct {
	tokenUtil  validator.TokenValidator
	httpClient *http.Client
}

type TokenResponse struct {
	AccessToken   *string `json:"access_token"`
	IdentityToken *string `json:"id_token"`
	RefreshToken  *string `json:"refresh_token"`
	TokenType     *string `json:"token_type"`
	ExpiresIn     int     `json:"expires_in"`
}

type OauthCookie struct {
	Token      string
	Expiration time.Time
}

func New() strategy.Strategy {
	return &WebStrategy{
		tokenUtil: validator.New(),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (w *WebStrategy) HandleAuthnZRequest(r *authnz.HandleAuthnZRequest, actions []engine.PolicyAction) (*authnz.HandleAuthnZResponse, error) {
	props := strategy.DecodeValueMap(r.Instance.Action.Properties)
	isAuthorized, err := w.checkAuthorized(props)
	if err != nil {
		return nil, err
	}
	if isAuthorized {
		log.Debug("User already authenticated")
		return &authnz.HandleAuthnZResponse{
			Result: &v1beta1.CheckResult{Status: status.OK},
		}, nil
	}
	if err, found := props[oauthQueryError]; found && err != "" {
		log.Debugf("An error occurred during authentication : %s", err)
		return w.handleErrorCallback(errors.New(err.(string)))
	}
	if code, found := props[authorizationCode]; found && code != "" {
		log.Debugf("Received authorization code : %s", code)
		return w.handleAuthorizationCodeCallback(code, actions)
	}
	log.Debug("Handling new user authentication")
	return w.handleAuthorizationCodeFlow(actions)
}

func (w *WebStrategy) checkAuthorized(props map[string]interface{}) (bool, error) {
	// Convert tokens
	return false, nil
}

func (w *WebStrategy) handleErrorCallback(err error) (*authnz.HandleAuthnZResponse, error) {
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{Status: rpc.Status{
			Code:    int32(rpc.UNAUTHENTICATED),
			Message: err.Error(),
		}},
	}, nil
}

func (w *WebStrategy) handleAuthorizationCodeCallback(code interface{}, actions []engine.PolicyAction) (*authnz.HandleAuthnZResponse, error) {
	if len(actions) < 1 {
		return nil, nil
	}
	p := actions[0]

	// Get Tokens
	response, err := w.getTokens(code.(string), "http://localhost:3000/api/user/data", p.Client)
	if err != nil {
		log.Errorf("Could not retrieve tokens : %s", err.Error())
		return w.handleErrorCallback(err)
	}

	tokens := validator.RawTokens{
		Access: *response.AccessToken,
		ID:     *response.IdentityToken,
	}

	// Validate Tokens
	oauthErr := w.tokenUtil.Validate(tokens, actions)
	if oauthErr != nil {
		log.Debugf("Failed token validation: %v", oauthErr)
		return w.handleErrorCallback(err)
	}

	// Create access_token cookie
	accessTokenCookie, err := generateCookie(&OauthCookie{
		Token: *response.AccessToken,
	})
	if err != nil {
		log.Debugf("Could not generate cookie: %v", err)
		return nil, err
	}

	// Create id_token cookie
	idTokenCookie, err := generateCookie(&OauthCookie{
		Token: *response.IdentityToken,
	})
	if err != nil {
		log.Debugf("Could not generate cookie: %v", err)
		return nil, err
	}

	log.Debug("Authenticated. Returning cookies.")

	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.OK), // Response tells Mixer to accept request
				Message: "Successfully authenticated",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Headers: map[string]string{setCookie: accessTokenCookie.String(), setCookie + ": identity": idTokenCookie.String()},
				})},
			},
		},
		Output: &authnz.OutputMsg{
			AccessTokenCookie: accessTokenCookie.String(),
			IdTokenCookie:     idTokenCookie.String(),
		},
	}, nil
}

func (w *WebStrategy) handleAuthorizationCodeFlow(actions []engine.PolicyAction) (*authnz.HandleAuthnZResponse, error) {
	if len(actions) < 1 {
		return nil, nil
	}
	p := actions[0] // Redirect to this identity provider

	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: "Redirecting to identity provider",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code:    policy.Found, // Response Mixer remaps on request
					Headers: map[string]string{location: generateAuthorizationUrl(p.Client)},
				})},
			},
		},
	}, nil
}

func (w *WebStrategy) getTokens(code string, redirectURI string, client *client.Client) (*TokenResponse, error) {

	form := url.Values{}
	form.Add("client_id", client.ClientId)
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", client.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Errorf("Failed to retrieve tokens")
		return nil, err
	}

	req.SetBasicAuth(client.ClientId, client.ClientSecret)
	req.Header.Set("xFilterType", "IstioAdapter")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := w.httpClient.Do(req)
	if err != nil {
		log.Errorf("Failed to get tokens : %s", err)
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		log.Debugf("Unexpected response - status code: %d , msg: %s", res.StatusCode, string(body))
		return nil, fmt.Errorf("token endpoint returned non 200 status code: %d", res.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Debugf("Could not parse request body - status code: %d , msg: %s", res.StatusCode, string(body))
		return nil, err
	}

	return &tokenResponse, nil
}

func generateCookie(cookieData *OauthCookie) (*http.Cookie, error) {
	// encode the struct
	data, err := bson.Marshal(&cookieData)
	if err != nil {
		return nil, err
	}

	// create the cookie
	if encoded, err := secretCookie.Encode(adapterCookie, data); err == nil {
		return &http.Cookie{
			Name:     adapterCookie,
			Value:    encoded,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			Expires:  time.Now().Add(time.Hour * time.Duration(4)),
		}, nil
	} else {
		log.Infof("Error encoding the cookie length is %s", encoded)
		return nil, err
	}
}

func generateAuthorizationUrl(c *client.Client) string {
	baseUrl, err := url.Parse(c.AuthURL)
	if err != nil {
		log.Errorf("Malformed Auth URL: %s", err.Error())
		return ""
	}

	// Prepare Query Parameters
	params := url.Values{}
	params.Add("client_id", c.ClientId)
	params.Add("response_type", "code")
	params.Add("redirect_uri", "http://localhost:3000/api/user/data")
	params.Add("scope", "oidc")

	// Add Query Parameters to the URL
	baseUrl.RawQuery = params.Encode() // Escape Query Parameters

	return baseUrl.String()
}

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
	accessTokenCookie = "ibmcloudappid-access-cookie"
	idTokenCookie     = "ibmcloudappid-identity-cookie"
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
	isAuthorized, err := w.checkAuthorized(r.Instance.Subject.Credentials)
	if err != nil {
		return nil, err
	}
	if isAuthorized {
		log.Debug("User already authenticated")
		return &authnz.HandleAuthnZResponse{
			Result: &v1beta1.CheckResult{Status: status.OK},
		}, nil
	}
	props := strategy.DecodeValueMap(r.Instance.Action.Properties)
	if err, found := props[oauthQueryError]; found && err != "" {
		log.Debugf("An error occurred during authentication : %s", err)
		return w.handleErrorCallback(errors.New(err.(string)))
	}
	if code, found := props[authorizationCode]; found && code != "" {
		log.Debugf("Received authorization code : %s", code)
		return w.handleAuthorizationCodeCallback(code, r.Instance.Action, actions)
	}
	log.Debug("Handling new user authentication")
	return w.handleAuthorizationCodeFlow(r.Instance.Action, actions)
}

func (w *WebStrategy) checkAuthorized(credentials *authnz.CredentialsMsg) (bool, error) {
	// Parse cookies
	header := http.Header{}
	header.Add("Cookie", credentials.Cookies)
	request := http.Request{Header: header}

	cookies := request.Cookies()
	accessCookie := getCookieByName(cookies, accessTokenCookie)
	idCookie := getCookieByName(cookies, idTokenCookie)

	if accessCookie != "" {
		if idCookie != "" {

		}
		return true, nil
	}
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

func (w *WebStrategy) handleAuthorizationCodeCallback(code interface{}, action *authnz.ActionMsg, actions []engine.PolicyAction) (*authnz.HandleAuthnZResponse, error) {
	if len(actions) < 1 {
		return nil, nil
	}
	p := actions[0]

	redirectURI, _ := buildRedirectURI(action)

	// Get Tokens
	response, err := w.getTokens(code.(string), redirectURI, p.Client)
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
	accessTokenCookie, err := generateCookie(accessTokenCookie, &OauthCookie{
		Token: *response.AccessToken,
	})
	if err != nil {
		log.Debugf("Could not generate cookie: %v", err)
		return nil, err
	}

	// Create id_token cookie
	idTokenCookie, err := generateCookie(idTokenCookie, &OauthCookie{
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
			},
		},
		Output: &authnz.OutputMsg{
			AccessTokenCookie: accessTokenCookie.String(),
			IdTokenCookie:     idTokenCookie.String(),
		},
	}, nil
}

func (w *WebStrategy) handleAuthorizationCodeFlow(action *authnz.ActionMsg, actions []engine.PolicyAction) (*authnz.HandleAuthnZResponse, error) {
	if len(actions) < 1 {
		return nil, nil
	}
	p := actions[0] // Redirect to this identity provider
	redirectURI, _ := buildRedirectURI(action)
	log.Infof("Initiating redirect to identity provider using redirect URL: %s", redirectURI)
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: "Redirecting to identity provider",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code:    policy.Found, // Response Mixer remaps on request
					Headers: map[string]string{location: generateAuthorizationUrl(p.Client, redirectURI)},
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

func generateCookie(cookieName string, cookieData *OauthCookie) (*http.Cookie, error) {
	// encode the struct
	data, err := bson.Marshal(&cookieData)
	if err != nil {
		return nil, err
	}

	// create the cookie
	if encoded, err := secretCookie.Encode(cookieName, data); err == nil {
		return &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Path:     "/",
			Secure:   false, // TODO: DO NOT RELEASE WITHOUT THIS FLAG SET TO TRUE
			HttpOnly: false,
			Expires:  time.Now().Add(time.Hour * time.Duration(4)),
		}, nil
	} else {
		log.Infof("Error encoding the cookie length is %s", encoded)
		return nil, err
	}
}

func generateAuthorizationUrl(c *client.Client, redirectURI string) string {
	baseUrl, err := url.Parse(c.AuthURL)
	if err != nil {
		log.Errorf("Malformed Auth URL: %s", err.Error())
		return ""
	}

	// Prepare Query Parameters
	params := url.Values{}
	params.Add("client_id", c.ClientId)
	params.Add("response_type", "code")
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", "oidc")

	// Add Query Parameters to the URL
	baseUrl.RawQuery = params.Encode() // Escape Query Parameters

	return baseUrl.String()
}

// getCookieByName finds the given cookie in an array
func getCookieByName(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func buildRedirectURI(action *authnz.ActionMsg) (string, error) {
	props := strategy.DecodeValueMap(action.Properties)
	// Generate Redirect URI - TODO: error checking
	reqScheme := props["request_scheme"].(string)
	reqHost := props["request_host"].(string)
	reqUrl := props["request_url_path"].(string)
	return reqScheme + "://" + reqHost + reqUrl, nil
}

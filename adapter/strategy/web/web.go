package webstrategy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"github.com/gorilla/securecookie"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/strategy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/validator"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"gopkg.in/mgo.v2/bson"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/pkg/log"
)

const (
	bearer            = "Bearer"
	callbackEndpoint  = "/oidc/callback"
	location          = "location"
	setCookie         = "Set-Cookie"
	accessTokenCookie = "ibmcloudappid-access-cookie"
	idTokenCookie     = "ibmcloudappid-identity-cookie"
)

var hashKey = securecookie.GenerateRandomKey(32)
var blockKey = securecookie.GenerateRandomKey(16)
var secretCookie = securecookie.New(hashKey, blockKey)

// WebStrategy handles OAuth 2.0 / OIDC flows
type WebStrategy struct {
	tokenUtil  validator.TokenValidator
	httpClient *networking.HttpClient
}

// TokenResponse models an OAuth 2.0 /Token endpoint response
type TokenResponse struct {
	// The OAuth 2.0 Access Token
	AccessToken *string `json:"access_token"`
	// The OIDC ID Token
	IdentityToken *string `json:"id_token"`
	// The OAuth 2.0 Refresh Token
	RefreshToken *string `json:"refresh_token"`
	// The token expiration time
	ExpiresIn int `json:"expires_in"`
}

// OidcCookie represents a token stored in browser
type OidcCookie struct {
	Token      string
	Expiration time.Time
}

// New creates an instance of an OIDC protection agent.
func New() strategy.Strategy {
	return &WebStrategy{
		tokenUtil:  validator.New(),
		httpClient: networking.New(),
	}
}

// HandleAuthnZRequest acts as the entry point to an OAuth 2.0 / OIDC flow. It processes OAuth 2.0 / OIDC requests.
func (w *WebStrategy) HandleAuthnZRequest(r *authnz.HandleAuthnZRequest, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	tokens, err := w.isAuthorized(r.Instance.Request.Headers.Cookies, action)
	if err != nil {
		return nil, err
	}
	if tokens != nil {
		log.Debug("User is already authenticated")
		// If in a callback flow, redirect to original endpoint. Cookies are already stored/valid
		if strings.HasSuffix(r.Instance.Request.Path, callbackEndpoint) {
			return buildSuccessRedirectResponse(r.Instance.Request.Path, nil), nil
		}
		// Pass request through to service
		return &authnz.HandleAuthnZResponse{
			Result: &v1beta1.CheckResult{Status: status.OK},
			Output: &authnz.OutputMsg{
				Authorization: "Bearer " + tokens.Access + " " + tokens.ID,
			},
		}, nil
	}

	if strings.HasSuffix(r.Instance.Request.Path, callbackEndpoint) {
		if r.Instance.Request.Params.Error != "" {
			log.Debugf("An error occurred during authentication : %s", r.Instance.Request.Params.Error)
			return w.handleErrorCallback(errors.New(r.Instance.Request.Params.Error))
		} else if r.Instance.Request.Params.Code != "" {
			log.Debugf("Received authorization code : %s", r.Instance.Request.Params.Code)
			return w.handleAuthorizationCodeCallback(r.Instance.Request.Params.Code, r.Instance.Request, action)
		} else {
			log.Infof("Unexpected response on callback endpoint /oidc/callback. Triggering re-authentication.")
		}
	}
	log.Debug("Handling new user authentication")
	return w.handleAuthorizationCodeFlow(r.Instance.Request, action)
}

// isAuthorized checks for the existence of valid cookies
// returns an error in the event of an Internal Server Error
func (w *WebStrategy) isAuthorized(cookies string, action *engine.Action) (*validator.RawTokens, error) {
	if action.Client == nil {
		log.Errorf("Internal server error: OIDC client not provided")
		return nil, errors.New("invalid OIDC configuration")
	}

	header := http.Header{}
	header.Add("Cookie", cookies)
	request := http.Request{Header: header}

	accessCookie, err := request.Cookie(buildTokenCookieName(accessTokenCookie, action.Client))
	accessTokenCookie := parseAndValidateCookie(accessCookie)
	if accessTokenCookie == nil {
		log.Debugf("Valid access token cookie not found: %v", err)
		return nil, nil
	}

	validationErr := w.tokenUtil.Validate(accessTokenCookie.Token, action.Client.AuthorizationServer().KeySet(), action.Rules)
	if validationErr != nil {
		log.Debugf("Cookies failed token validation: %v", validationErr)
		return nil, nil
	}

	/*
		idCookie, err := request.Cookie(buildTokenCookieName(idTokenCookie, action.Client))
		idTokenCookie := parseAndValidateCookie(accessCookie)
		if accessTokenCookie == nil {
			log.Debugf("Valid ID token cookie not found: %v", err)
			return nil, nil
		}

		validationErr = w.tokenUtil.Validate(idTokenCookie.Token, action.Client.AuthorizationServer.KeySet(), action.Rules)
		if validationErr != nil {
			log.Debugf("Cookies failed token validation: %v", validationErr)
			return nil, nil
		}
	*/
	return &validator.RawTokens{Access: accessTokenCookie.Token}, nil
}

// handleErrorCallback returns an Unauthenticated CheckResult
func (w *WebStrategy) handleErrorCallback(err error) (*authnz.HandleAuthnZResponse, error) {
	message := "internal server error"
	if err != nil {
		message = err.Error()
	}
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{Status: rpc.Status{
			Code:    int32(rpc.UNAUTHENTICATED),
			Message: message,
		}},
	}, nil
}

// handleAuthorizationCodeCallback processes a successful OAuth 2.0 callback containing a authorization code
func (w *WebStrategy) handleAuthorizationCodeCallback(code interface{}, request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {

	redirectURI := buildRequestURL(request)

	// Get Tokens
	response, err := w.getTokens(code.(string), redirectURI, action.Client)
	if err != nil {
		log.Errorf("Could not retrieve tokens : %s", err.Error())
		return w.handleErrorCallback(err)
	}

	// Validate Tokens
	validationErr := w.tokenUtil.Validate(*response.AccessToken, action.Client.AuthorizationServer().KeySet(), action.Rules)
	if validationErr != nil {
		log.Debugf("Cookies failed token validation: %v", validationErr)
		return w.handleErrorCallback(err)
	}

	validationErr = w.tokenUtil.Validate(*response.IdentityToken, action.Client.AuthorizationServer().KeySet(), action.Rules)
	if validationErr != nil {
		log.Debugf("Cookies failed token validation: %v", validationErr)
		return w.handleErrorCallback(err)
	}

	// Create access_token cookie
	accessTokenCookie, err := generateTokenCookie(buildTokenCookieName(accessTokenCookie, action.Client), &OidcCookie{
		Token:      *response.AccessToken,
		Expiration: time.Now().Add(time.Minute * time.Duration(response.ExpiresIn)),
	})
	if err != nil {
		log.Debugf("Could not generate cookie: %v", err)
		return nil, err
	}

	// Create id_token cookie
	/*
		_, err = generateTokenCookie(idTokenCookie, &OidcCookie{
			Token: *response.IdentityToken,
		})
		if err != nil {
			log.Debugf("Could not generate cookie: %v", err)
			return nil, err
		}
	*/

	originalURL := strings.Split(redirectURI, callbackEndpoint)[0]
	log.Debugf("Authenticated. Redirecting to %v", originalURL)
	return buildSuccessRedirectResponse(originalURL, []*http.Cookie{accessTokenCookie}), nil
}

// handleAuthorizationCodeFlow initiates an OAuth 2.0 / OIDC authorization_code grant flow.
func (w *WebStrategy) handleAuthorizationCodeFlow(request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	redirectURI := buildRequestURL(request) + callbackEndpoint
	log.Infof("Initiating redirect to identity provider using redirect URL: %s", redirectURI)
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: "Redirecting to identity provider",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code:    policy.Found, // Response Mixer remaps on request
					Headers: map[string]string{location: generateAuthorizationUrl(action.Client, redirectURI)},
				})},
			},
		},
	}, nil
}

// getTokens retrieves tokens from the authorization server using the authorization grant code
func (w *WebStrategy) getTokens(code string, redirectURI string, client client.Client) (*TokenResponse, error) {

	form := url.Values{}
	form.Add("client_id", client.ID())
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", client.AuthorizationServer().TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		log.Errorf("Failed to retrieve tokens")
		return nil, err
	}

	req.SetBasicAuth(client.ID(), client.Secret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tokenResponse TokenResponse
	if err := w.httpClient.Do(req, http.StatusOK, &tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

// buildSuccessRedirectResponse constructs a HandleAuthnZResponse containing a 302 redirect
// to the provided url with the accompanying cookie headers
func buildSuccessRedirectResponse(redirectURI string, cookies []*http.Cookie) *authnz.HandleAuthnZResponse {
	headers := make(map[string]string)
	headers[location] = strings.Split(redirectURI, callbackEndpoint)[0]
	for _, cookie := range cookies {
		headers[setCookie] = cookie.String()
	}
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: "Successfully authenticated : redirecting to original URL",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code:    policy.Found, // Response Mixer remaps on request
					Headers: headers,
				})},
			},
		},
	}
}

// generateTokenCookie creates an http.Cookie
func generateTokenCookie(cookieName string, cookieData *OidcCookie) (*http.Cookie, error) {
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

// generateAuthorizationUrl builds the /authorization request that begins an OAuth 2.0 / OIDC flow
func generateAuthorizationUrl(c client.Client, redirectURI string) string {
	baseUrl, err := url.Parse(c.AuthorizationServer().AuthorizationEndpoint())
	if err != nil {
		log.Errorf("Malformed Auth URL: %s", err.Error())
		return ""
	}

	// Prepare Query Parameters
	params := url.Values{}
	params.Add("client_id", c.ID())
	params.Add("response_type", "code")
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", "oidc")

	// Add Query Parameters to the URL
	baseUrl.RawQuery = params.Encode() // Escape Query Parameters

	return baseUrl.String()
}

// parseAndValidateCookie
func parseAndValidateCookie(cookie *http.Cookie) *OidcCookie {
	if cookie == nil {
		log.Debugf("Cookie does not exist")
		return nil
	}
	value := []byte{}
	if err := secretCookie.Decode(cookie.Name, cookie.Value, &value); err != nil {
		log.Debugf("Could not read cookie: %v", err)
		return nil
	}
	cookieObj := OidcCookie{}
	if err := bson.Unmarshal(value, &cookieObj); err != nil {
		log.Debugf("Could not parse cookie data: %v", err)
		return nil
	}
	if cookieObj.Token == "" {
		log.Debugf("Missing token value")
		return nil
	}
	if cookieObj.Expiration.Before(time.Now()) {
		log.Debugf("Cookies have expired: %v - %v", cookieObj.Expiration, time.Now())
		return nil
	}
	return &cookieObj
}

// buildRequestURL constructs the original url from the request object
func buildRequestURL(action *authnz.RequestMsg) string {
	return action.Scheme + "://" + action.Host + action.Path
}

// buildTokenCookieName constructs the cookie name
func buildTokenCookieName(base string, c client.Client) string {
	return base + "-" + c.ID()
}

func (r *TokenResponse) OK() error {
	if r.AccessToken == nil {
		return errors.New("invalid token endpoint response: access_token does not exist")
	}
	return nil
}

package webstrategy

import (
	"errors"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	bearer            = "Bearer"
	logoutEndpoint    = "/oidc/logout"
	callbackEndpoint  = "/oidc/callback"
	location          = "location"
	setCookie         = "Set-Cookie"
	accessTokenCookie = "ibmcloudappid-access-cookie"
	//idTokenCookie     = "ibmcloudappid-identity-cookie"
	hashKey          = "HASH_KEY"
	blockKey         = "BLOCK_KEY"
	defaultNamespace = "istio-system"
	defaultKeySecret = "ibmcloudappid-cookie-sig-enc-keys"
)

// WebStrategy handles OAuth 2.0 / OIDC flows
type WebStrategy struct {
	tokenUtil  validator.TokenValidator
	httpClient *networking.HttpClient
	kubeClient kubernetes.Interface

	// mutex protects all fields below
	mutex        *sync.Mutex
	secureCookie *securecookie.SecureCookie
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
func New(kubeClient kubernetes.Interface) strategy.Strategy {
	w := &WebStrategy{
		tokenUtil:  validator.New(),
		httpClient: networking.New(),
		kubeClient: kubeClient,
		mutex:      &sync.Mutex{},
	}

	// Instantiate the secure cookie encryption instance by
	// reading or creating a new HMAC and AES symmetric key
	_, err := w.getSecureCookie()
	if err != nil {
		zap.L().Warn("Could not sync signing / encryption secrets, will retry later", zap.Error(err))
	}

	return w
}

// HandleAuthnZRequest acts as the entry point to an OAuth 2.0 / OIDC flow. It processes OAuth 2.0 / OIDC requests.
func (w *WebStrategy) HandleAuthnZRequest(r *authnz.HandleAuthnZRequest, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	if strings.HasSuffix(r.Instance.Request.Path, logoutEndpoint) {
		zap.L().Debug("Received logout request.", zap.String("client_name", action.Client.Name()))
		return w.handleLogout(r.Instance.Request.Path, action)
	}

	if strings.HasSuffix(r.Instance.Request.Path, callbackEndpoint) {
		if r.Instance.Request.Params.Error != "" {
			zap.L().Debug("An error occurred during authentication", zap.String("error_query_param", r.Instance.Request.Params.Error))
			return w.handleErrorCallback(errors.New(r.Instance.Request.Params.Error))
		} else if r.Instance.Request.Params.Code != "" {
			zap.L().Debug("Received authorization code")
			return w.handleAuthorizationCodeCallback(r.Instance.Request.Params.Code, r.Instance.Request, action)
		} else {
			zap.L().Debug("Unexpected response on callback endpoint /oidc/callback. Triggering re-authentication.")
			return w.handleAuthorizationCodeFlow(r.Instance.Request, action)
		}
	}

	// Not in an OAuth 2.0 / OIDC flow, check for current authn/z session
	res, err := w.isAuthorized(r.Instance.Request.Headers.Cookies, action)
	if res != nil || err != nil {
		return res, err
	}
	zap.L().Debug("Handling new user authentication")
	return w.handleAuthorizationCodeFlow(r.Instance.Request, action)
}

// isAuthorized checks for the existence of valid cookies
// returns an error in the event of an Internal Server Error
func (w *WebStrategy) isAuthorized(cookies string, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	if action.Client == nil {
		zap.L().Warn("Internal server error: OIDC client not provided")
		return nil, errors.New("invalid OIDC configuration")
	}

	header := http.Header{}
	header.Add("Cookie", cookies)
	request := http.Request{Header: header}

	accessCookie, err := request.Cookie(buildTokenCookieName(accessTokenCookie, action.Client))
	accessTokenCookie := w.parseAndValidateCookie(accessCookie)
	if accessTokenCookie == nil {
		zap.L().Debug("Valid access token cookie not found: %v", zap.Error(err))
		return nil, nil
	}

	validationErr := w.tokenUtil.Validate(accessTokenCookie.Token, action.Client.AuthorizationServer().KeySet(), action.Rules)
	if validationErr != nil {
		zap.L().Debug("Cookies failed token validation: %v", zap.Error(validationErr))
		return nil, nil
	}

	// TODO: Validate ID token cookie here

	zap.L().Debug("User is currently authenticated")
	// Pass request through to service
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{Status: status.OK},
		Output: &authnz.OutputMsg{
			Authorization: strings.Join([]string{bearer, accessTokenCookie.Token}, " "),
		},
	}, nil
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

// handleLogout processes logout requests by deleting session cookies and returning to the base path
func (w *WebStrategy) handleLogout(path string, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	expiration := time.Now().Add(-100 * time.Hour)
	cookies := make([]*http.Cookie, 1) // TODO: Change to 3 and add other tokens when supported
	for i, name := range []string{accessTokenCookie} {
		cookies[i] = &http.Cookie{
			Name:    buildTokenCookieName(name, action.Client),
			Value:   "deleted",
			Path:    "/",
			Expires: expiration,
		}
	}
	redirectURL := strings.Split(path, logoutEndpoint)[0]
	return buildSuccessRedirectResponse(redirectURL, cookies), nil
}

// handleAuthorizationCodeCallback processes a successful OAuth 2.0 callback containing a authorization code
func (w *WebStrategy) handleAuthorizationCodeCallback(code interface{}, request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {

	redirectURI := buildRequestURL(request)

	// Get Tokens
	response, err := w.getTokens(code.(string), redirectURI, action.Client)
	if err != nil {
		zap.L().Info("Could not retrieve tokens", zap.Error(err))
		return w.handleErrorCallback(err)
	}

	// Validate Tokens
	validationErr := w.tokenUtil.Validate(*response.AccessToken, action.Client.AuthorizationServer().KeySet(), action.Rules)
	if validationErr != nil {
		zap.L().Debug("Cookies failed token validation", zap.Error(validationErr))
		return w.handleErrorCallback(err)
	}

	validationErr = w.tokenUtil.Validate(*response.IdentityToken, action.Client.AuthorizationServer().KeySet(), action.Rules)
	if validationErr != nil {
		zap.L().Debug("Cookies failed token validation", zap.Error(validationErr))
		return w.handleErrorCallback(err)
	}

	// Create access_token cookie
	accessTokenCookie, err := w.generateTokenCookie(buildTokenCookieName(accessTokenCookie, action.Client), &OidcCookie{
		Token:      *response.AccessToken,
		Expiration: time.Now().Add(time.Minute * time.Duration(response.ExpiresIn)),
	})
	if err != nil {
		zap.L().Debug("Could not generate cookie", zap.Error(err))
		return nil, err
	}

	// TODO: generate ID encrypted token cookie

	originalURL := strings.Split(redirectURI, callbackEndpoint)[0]
	zap.S().Debugf("Authenticated. Redirecting to %s", originalURL)
	return buildSuccessRedirectResponse(originalURL, []*http.Cookie{accessTokenCookie}), nil
}

// handleAuthorizationCodeFlow initiates an OAuth 2.0 / OIDC authorization_code grant flow.
func (w *WebStrategy) handleAuthorizationCodeFlow(request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	redirectURI := buildRequestURL(request) + callbackEndpoint
	zap.S().Debugf("Initiating redirect to identity provider using redirect URL: %s", redirectURI)
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
		zap.L().Warn("Could not serialize HTTP request", zap.Error(err))
		return nil, err
	}

	req.SetBasicAuth(client.ID(), client.Secret())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tokenResponse TokenResponse
	if err := w.httpClient.Do(req, http.StatusOK, &tokenResponse); err != nil {
		zap.L().Info("Failed to retrieve tokens", zap.Error(err))
		return nil, err
	}

	return &tokenResponse, nil
}

// getSecureCookie retrieves the SecureCookie encryption struct in a
// thread safe manner.
func (w *WebStrategy) getSecureCookie() (*securecookie.SecureCookie, error) {
	// Allow all threads to check if instance already exists
	if w.secureCookie != nil {
		return w.secureCookie, nil
	}
	w.mutex.Lock()
	// Once this thread has the lock check again to see if it had been set while waiting
	if w.secureCookie != nil {
		w.mutex.Unlock()
		return w.secureCookie, nil
	}
	// We need to generate a new key set
	sc, err := w.generateSecureCookie()
	w.mutex.Unlock()
	return sc, err
}

// generateSecureCookie instantiates a SecureCookie instance using either the preconfigured
// key secret cookie or a dynamically generated pair.
func (w *WebStrategy) generateSecureCookie() (*securecookie.SecureCookie, error) {
	var secret interface{}
	// Check if key set was already configured. This should occur during helm install
	secret, err := networking.Retry(3, 1, func() (interface{}, error) {
		return w.kubeClient.CoreV1().Secrets(defaultNamespace).Get(defaultKeySecret, metav1.GetOptions{})
	})

	if err != nil {
		zap.S().Infof("Secret %v not found: %v. Another will be generated.", defaultKeySecret, err)
		secret, err = w.generateKeySecret(32, 16)
		if err != nil {
			zap.L().Info("Failed to retrieve tokens", zap.Error(err))
			return nil, err
		}
	}

	if s, ok := secret.(*v1.Secret); ok {
		zap.S().Infof("Synced secret: %v", defaultKeySecret)
		w.secureCookie = securecookie.New(s.Data[hashKey], s.Data[blockKey])
		return w.secureCookie, nil
	} else {
		zap.S().Error("Could not convert interface to secret")
		return nil, errors.New("could not sync signing / encryption secrets")
	}
}

// generateKeySecret builds and stores a key pair used for the signing and encryption
// of session cookies.
func (w *WebStrategy) generateKeySecret(hashKeySize int, blockKeySize int) (interface{}, error) {
	data := make(map[string][]byte)
	data[hashKey] = securecookie.GenerateRandomKey(hashKeySize)
	data[blockKey] = securecookie.GenerateRandomKey(blockKeySize)

	newSecret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultKeySecret,
			Namespace: defaultNamespace,
		},
		Data: data,
	}

	return networking.Retry(3, 1, func() (interface{}, error) {
		return w.kubeClient.CoreV1().Secrets(defaultNamespace).Create(&newSecret)
	})
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

// generateTokenCookie creates an encodes and encrypts cookieData into an http.Cookie
func (w *WebStrategy) generateTokenCookie(cookieName string, cookieData *OidcCookie) (*http.Cookie, error) {
	// encode the struct
	data, err := bson.Marshal(&cookieData)
	if err != nil {
		zap.L().Warn("Could not marshal cookie data", zap.Error(err))
		return nil, err
	}

	sc, err := w.getSecureCookie()
	if err != nil {
		zap.L().Warn("Could not get secure cookie instance", zap.Error(err))
		return nil, err
	}

	// create the cookie
	if encoded, err := sc.Encode(cookieName, data); err == nil {
		return &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Path:     "/",
			Secure:   false, // TODO: DO NOT RELEASE WITHOUT THIS FLAG SET TO TRUE
			HttpOnly: false,
			Expires:  time.Now().Add(time.Hour * time.Duration(4)),
		}, nil
	} else {
		zap.S().Error("Error encoding cookie: length: %s", len(encoded))
		return nil, err
	}
}

// generateAuthorizationUrl builds the /authorization request that begins an OAuth 2.0 / OIDC flow
func generateAuthorizationUrl(c client.Client, redirectURI string) string {
	baseUrl, err := url.Parse(c.AuthorizationServer().AuthorizationEndpoint())
	if err != nil {
		zap.L().Warn("Malformed Authorization URL", zap.Error(err))
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

// parseAndValidateCookie parses a raw http.Cookie, performs basic validation
// and returns an OIDCCookie
func (w *WebStrategy) parseAndValidateCookie(cookie *http.Cookie) *OidcCookie {
	if cookie == nil {
		zap.L().Debug("Cookie does not exist")
		return nil
	}
	sc, err := w.getSecureCookie()
	if err != nil {
		zap.L().Debug("Error getting securecookie", zap.Error(err))
		return nil
	}
	value := []byte{}
	if err := sc.Decode(cookie.Name, cookie.Value, &value); err != nil {
		zap.L().Debug("Could not decode cookie:", zap.Error(err))
		return nil
	}
	cookieObj := OidcCookie{}
	if err := bson.Unmarshal(value, &cookieObj); err != nil {
		zap.L().Debug("Could not unmarshal cookie:", zap.Error(err))
		return nil
	}
	if cookieObj.Token == "" {
		zap.L().Debug("Cookie does not have a token value")
		return nil
	}
	if cookieObj.Expiration.Before(time.Now()) {
		zap.S().Debug("Cookies have expired: %v - %v", cookieObj.Expiration, time.Now())
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

// OK validates a TokenResponse
func (r *TokenResponse) OK() error {
	if r.AccessToken == nil {
		return errors.New("invalid token endpoint response: access_token does not exist")
	}
	return nil
}

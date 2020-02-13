package webstrategy

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/client"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/config"
	oAuthError "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/errors"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/networking"
	policiesV1 "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	adapterPolicy "github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/strategy"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/validator"
	authnz "github.com/ibm-cloud-security/app-identity-and-access-adapter/config/template"
)

const (
	bearer           = "Bearer"
	logoutEndpoint   = "/oidc/logout"
	callbackEndpoint = "/oidc/callback"
	location         = "location"
	setCookie        = "Set-Cookie"
	sessionCookie    = "oidc-cookie"
	hashKey          = "HASH_KEY"
	blockKey         = "BLOCK_KEY"
	defaultNamespace = "istio-system"
	defaultKeySecret = "appidentityandaccessadapter-cookie-sig-enc-keys"

	// Cookies to use when we revert to statelessness
	// accessTokenCookie = "appidentityandaccessadapter-access-cookie"
	// idTokenCookie     = "appidentityandaccessadapter-identity-cookie"
	// refreshTokenCookie     = "appidentityandaccessadapter-identity-cookie"
)

// WebStrategy handles OAuth 2.0 / OIDC flows
type WebStrategy struct {
	ctx        *config.Config
	tokenUtil  validator.TokenValidator
	kubeClient kubernetes.Interface

	// mutex protects all fields below
	mutex      *sync.Mutex
	encrpytor  Encryptor
	tokenCache *sync.Map
}

// Encryptor signs and encrypts values. Used for cookie encryption
type Encryptor interface {
	Encode(name string, value interface{}) (string, error)
	Decode(name, value string, dst interface{}) error
}

// OidcCookie represents a token stored in browser
type OidcCookie struct {
	Value      string
	Expiration time.Time
}

// New creates an instance of an OIDC protection agent.
func New(ctx *config.Config, kubeClient kubernetes.Interface) strategy.Strategy {
	w := &WebStrategy{
		ctx:        ctx,
		tokenUtil:  validator.NewTokenValidator(adapterPolicy.OIDC),
		kubeClient: kubeClient,
		mutex:      &sync.Mutex{},
		tokenCache: new(sync.Map),
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
		return w.handleLogout(r, action)
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

	// Parse Cookies
	header := http.Header{}
	header.Add("Cookie", cookies)
	request := http.Request{Header: header}

	sessionCookie, err := request.Cookie(buildTokenCookieName(sessionCookie, action.Client))
	if err != nil {
		zap.L().Debug("Session cookie not provided", zap.String("client_name", action.Client.Name()))
		return nil, nil
	}

	// Load session information
	var session *authserver.TokenResponse
	if storedSession, ok := w.tokenCache.Load(sessionCookie.Value); !ok {
		zap.L().Debug("Session token does not exist", zap.String("client_name", action.Client.Name()))
		return nil, nil
	} else if session, ok = storedSession.(*authserver.TokenResponse); !ok {
		zap.L().Debug("Incompatible session token", zap.String("client_name", action.Client.Name()))
		return nil, nil
	}

	zap.L().Debug("Found active session", zap.String("client_name", action.Client.Name()), zap.String("session_id", sessionCookie.Value))

	// Validate session
	userInfoEndpoint := action.Client.AuthorizationServer().UserInfoEndpoint()
	keySet := action.Client.AuthorizationServer().KeySet()

	handleTokenValidationError := func(validationErr *oAuthError.OAuthError) (*authnz.HandleAuthnZResponse, error) {
		if validationErr.Msg == oAuthError.ExpiredTokenError().Msg {
			zap.L().Debug("Tokens have expired", zap.String("client_name", action.Client.Name()))
			return w.handleRefreshTokens(sessionCookie.Value, session, action.Client, action.Rules)
		}

		zap.L().Debug("Tokens are invalid - starting a new session", zap.String("client_name", action.Client.Name()), zap.String("session_id", sessionCookie.Value), zap.Error(validationErr))
		w.tokenCache.Delete(sessionCookie.Value)
		return nil, nil
	}

	if validationErr := w.tokenUtil.Validate(session.AccessToken, validator.Access, keySet, action.Rules, userInfoEndpoint); validationErr != nil {
		return handleTokenValidationError(validationErr)
	}

	if validationErr := w.tokenUtil.Validate(session.IdentityToken, validator.ID, keySet, action.Rules, userInfoEndpoint); validationErr != nil {
		return handleTokenValidationError(validationErr)
	}

	zap.L().Debug("User is currently authenticated")

	// Pass request through to service
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{Status: status.WithMessage(rpc.OK, "User is authenticated")},
		Output: &authnz.OutputMsg{
			Authorization: strings.Join([]string{bearer, session.AccessToken, session.IdentityToken}, " "),
		},
	}, nil
}

// handleRefreshTokens attempts to update an expired session using the refresh token flow
func (w *WebStrategy) handleRefreshTokens(sessionID string, session *authserver.TokenResponse, c client.Client, rules []policiesV1.Rule) (*authnz.HandleAuthnZResponse, error) {
	if session.RefreshToken == "" {
		zap.L().Debug("Refresh token not provided", zap.String("client_name", c.Name()))
		return nil, nil
	}
	userInfoEndpoint := c.AuthorizationServer().UserInfoEndpoint()
	keySet := c.AuthorizationServer().KeySet()

	if tokens, err := c.RefreshToken(session.RefreshToken); err != nil {
		zap.L().Info("Could not retrieve tokens using the refresh token", zap.String("client_name", c.Name()), zap.Error(err))
		return nil, nil
	} else if validationErr := w.tokenUtil.Validate(tokens.AccessToken, validator.Access, keySet, rules, userInfoEndpoint); validationErr != nil {
		zap.L().Debug("Could not validate Access tokens. Beginning a new session.", zap.String("client_name", c.Name()), zap.String("session_id", sessionID), zap.Error(validationErr))
		return nil, nil
	} else if validationErr := w.tokenUtil.Validate(tokens.IdentityToken, validator.ID, keySet, rules, userInfoEndpoint); validationErr != nil {
		zap.L().Debug("Could not validate Id tokens. Beginning a new session.", zap.String("client_name", c.Name()), zap.String("session_id", sessionID), zap.Error(validationErr))
		return nil, nil
	} else {
		zap.L().Debug("Updated tokens using refresh token", zap.String("client_name", c.Name()), zap.String("session_id", sessionID))
		cookie := generateSessionIDCookie(c, &sessionID)
		w.tokenCache.Store(cookie.Value, tokens)
		return &authnz.HandleAuthnZResponse{
			Result: &v1beta1.CheckResult{Status: status.WithMessage(rpc.OK, "User is authenticated")},
			Output: &authnz.OutputMsg{
				Authorization: strings.Join([]string{bearer, tokens.AccessToken, tokens.IdentityToken}, " "),
				SessionCookie: cookie.String(),
			},
		}, nil
	}
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
func (w *WebStrategy) handleLogout(r *authnz.HandleAuthnZRequest, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	header := http.Header{}
	header.Add("Cookie", r.Instance.Request.Headers.Cookies)
	request := http.Request{Header: header}
	cookieName := buildTokenCookieName(sessionCookie, action.Client)

	if cookie, err := request.Cookie(cookieName); err == nil {
		zap.L().Debug("Deleting active session", zap.String("client_name", action.Client.Name()), zap.String("session_id", cookie.Value))
		w.tokenCache.Delete(cookie.Value)
	}

	redirectURL := strings.Split(r.Instance.Request.Path, logoutEndpoint)[0]
	cookies := []*http.Cookie{
		{
			Name:    cookieName,
			Value:   "deleted",
			Path:    "/",
			Expires: time.Now().Add(-100 * time.Hour),
		},
	}
	return buildSuccessRedirectResponse(redirectURL, cookies), nil
}

/*
func (w *WebStrategy) handleLogout(path string, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	// Uncomment when we go stateless
	expiration := time.Now().Add(-100 * time.Hour)
	cookies := make([]*http.Cookie, 3)
	for i, name := range []string{accessTokenCookie, idTokenCookie, refreshTokenCookie} {
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
*/

// handleAuthorizationCodeCallback processes a successful OAuth 2.0 callback containing a authorization code
func (w *WebStrategy) handleAuthorizationCodeCallback(code interface{}, request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {

	err := w.validateState(request, action.Client)
	if err != nil {
		zap.L().Info("OIDC callback: could not validate state parameter", zap.Error(err), zap.String("client_name", action.Client.Name()))
		return w.handleErrorCallback(err)
	}

	redirectURI := buildRequestURL(request)

	// Exchange authorization grant code for tokens
	response, err := action.Client.ExchangeGrantCode(code.(string), redirectURI)
	if err != nil {
		zap.L().Info("OIDC callback: Could not retrieve tokens", zap.Error(err), zap.String("client_name", action.Client.Name()))
		return w.handleErrorCallback(err)
	}

	userInfoEndpoint := action.Client.AuthorizationServer().UserInfoEndpoint()
	keySet := action.Client.AuthorizationServer().KeySet()

	validationErr := w.tokenUtil.Validate(response.AccessToken, validator.Access, keySet, action.Rules, userInfoEndpoint)
	if validationErr != nil {
		zap.L().Info("OIDC callback: Access token failed validation", zap.Error(validationErr), zap.String("client_name", action.Client.Name()))
		return w.handleErrorCallback(validationErr)
	}

	validationErr = w.tokenUtil.Validate(response.IdentityToken, validator.ID, keySet, action.Rules, userInfoEndpoint)
	if validationErr != nil {
		zap.L().Info("OIDC callback: ID token failed validation", zap.Error(validationErr), zap.String("client_name", action.Client.Name()))
		return w.handleErrorCallback(validationErr)
	}

	cookie := generateSessionIDCookie(action.Client, nil)
	w.tokenCache.Store(cookie.Value, response)

	zap.L().Debug("OIDC callback: created new active session: ", zap.String("client_name", action.Client.Name()), zap.String("session_id", cookie.Value))

	if action.RedirectUri != "" {
		redirectURI = action.RedirectUri
	}

	return buildSuccessRedirectResponse(redirectURI, []*http.Cookie{cookie}), nil
}

// handleAuthorizationCodeFlow initiates an OAuth 2.0 / OIDC authorization_code grant flow.
func (w *WebStrategy) handleAuthorizationCodeFlow(request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	redirectURI := buildRequestURL(request) + callbackEndpoint
	// / Build and store session state
	state, stateCookie, err := w.buildStateParam(action.Client)
	if err != nil {
		zap.L().Info("Could not generate state parameter", zap.Error(err), zap.String("client_name", action.Client.Name()))
		return nil, err
	}
	zap.S().Debugf("Initiating redirect to identity provider using redirect URL: %s", redirectURI)
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: "Redirecting to identity provider",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code: policy.Found, // Response Mixer remaps on request
					Headers: map[string]string{
						location:  generateAuthorizationURL(action.Client, redirectURI, state),
						setCookie: stateCookie.String(),
					},
				})},
			},
		},
	}, nil
}

// getSecureCookie retrieves the SecureCookie encryption struct in a
// thread safe manner.
func (w *WebStrategy) getSecureCookie() (Encryptor, error) {
	// Allow all threads to check if instance already exists
	if w.encrpytor != nil {
		return w.encrpytor, nil
	}
	w.mutex.Lock()
	// Once this thread has the lock check again to see if it had been set while waiting
	if w.encrpytor != nil {
		w.mutex.Unlock()
		return w.encrpytor, nil
	}
	// We need to generate a new key set
	sc, err := w.generateSecureCookie()
	w.mutex.Unlock()
	return sc, err
}

// generateSecureCookie instantiates a SecureCookie instance using either the preconfigured
// key secret cookie or a dynamically generated pair.
func (w *WebStrategy) generateSecureCookie() (Encryptor, error) {
	var secret interface{}
	// Check if key set was already configured. This should occur during helm install
	secret, err := networking.Retry(3, 1, func() (interface{}, error) {
		return w.kubeClient.CoreV1().Secrets(defaultNamespace).Get(defaultKeySecret, metav1.GetOptions{})
	})

	if err != nil {
		zap.S().Infof("Secret %v not found: %v. Another will be generated.", defaultKeySecret, err)
		secret, err = w.generateKeySecret(w.ctx.HashKeySize.Value, w.ctx.BlockKeySize.Value)
		if err != nil {
			zap.L().Info("Failed to retrieve tokens", zap.Error(err))
			return nil, err
		}
	}

	if s, ok := secret.(*v1.Secret); ok {
		zap.S().Infof("Synced secret: %v", defaultKeySecret)
		w.encrpytor = securecookie.New(s.Data[hashKey], s.Data[blockKey])
		return w.encrpytor, nil
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

// generateEncryptedCookie creates an encodes and encrypts cookieData into an http.Cookie
func (w *WebStrategy) generateEncryptedCookie(cookieName string, cookieData *OidcCookie) (*http.Cookie, error) {
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
	if cookieObj.Value == "" {
		zap.L().Debug("Cookie does not have a token value")
		return nil
	}
	if cookieObj.Expiration.Before(time.Now()) {
		zap.S().Debug("Cookies have expired: %v - %v", cookieObj.Expiration, time.Now())
		return nil
	}
	return &cookieObj
}

// buildSuccessRedirectResponse constructs a HandleAuthnZResponse containing a 302 redirect
// to the provided url with the accompanying cookie headers
func buildSuccessRedirectResponse(redirectURI string, cookies []*http.Cookie) *authnz.HandleAuthnZResponse {
	headers := make(map[string]string)
	headers[location] = strings.Split(redirectURI, callbackEndpoint)[0]
	for _, cookie := range cookies {
		headers[setCookie] = cookie.String()
		zap.S().Debugf("Appending cookie to response: %s", cookie.String())
	}
	zap.S().Debugf("Authenticated. Redirecting to %s", headers[location])
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

func (w *WebStrategy) buildStateParam(c client.Client) (string, *http.Cookie, error) {
	state := randString(10)
	cookieName := buildTokenCookieName(sessionCookie, c)
	cookie, err := w.generateEncryptedCookie(cookieName, &OidcCookie{
		Value:      state,
		Expiration: time.Now().Add(time.Hour),
	})
	return state, cookie, err
}

// validateState ensures the callback request state parameter matches the state stored in an encrypted session cookie
// Follows from OAuth 2.0 specification https://tools.ietf.org/html/rfc6749#section-4.1.1
func (w *WebStrategy) validateState(request *authnz.RequestMsg, c client.Client) error {
	// Get state cookie from header
	header := http.Header{
		"Cookie": {request.Headers.Cookies},
	}
	r := http.Request{Header: header}
	name := buildTokenCookieName(sessionCookie, c)
	oidcStateCookie, err := r.Cookie(name)
	if err != nil {
		return errors.New("state parameter not provided")
	}

	// Parse encrypted state cookie
	storedHttpCookie := w.parseAndValidateCookie(oidcStateCookie)

	// Ensure state cookie is returned
	if storedHttpCookie == nil {
		stateError := errors.New("missing state parameter")
		zap.L().Info("OIDC callback: missing stored state parameter", zap.Error(err))
		return stateError
	}

	// Ensure state is returned on request from identity provider
	if request.Params.State == "" {
		stateError := errors.New("missing state parameter from callback")
		zap.L().Info("OIDC callback: missing state parameter from identity provider", zap.Error(err))
		return stateError
	}

	// Validate cookie state with stored state
	if request.Params.State != storedHttpCookie.Value {
		stateError := errors.New("invalid state parameter")
		zap.L().Info("OIDC callback: missing or invalid state parameter", zap.Error(err))
		return stateError
	}

	zap.L().Debug("OIDC callback: validated state parameter")

	return nil
}

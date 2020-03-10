package webstrategy

import (
	"errors"
	"net/http"
	"net/url"
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

// OidcState represents a state passed to the OIDC provider during auth flow and later validated
type OidcState struct {
	OriginalURL string
	Expiration  time.Time
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
	_, err := w.getEncryptionSecret()
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

	request := r.Instance.Request

	if client.IsCallbackRequest(action.Client, request.Scheme, request.Host, request.Path) {
		if r.Instance.Request.Params.Error != "" {
			zap.L().Debug("An error occurred during authentication", zap.String("error_query_param", request.Params.Error))
			return w.handleErrorCallback(errors.New(request.Params.Error))
		} else if request.Params.Code != "" {
			zap.L().Debug("Received authorization code")
			return w.handleAuthorizationCodeCallback(r.Instance.Request.Params.Code, request, action)
		} else {
			zap.L().Debug("Unexpected response on callback endpoint /oidc/callback. Triggering re-authentication.")
			return w.handleAuthorizationCodeFlow(request, action)
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
		zap.L().Debug("Current session does not exist.", zap.String("client_name", action.Client.Name()))
		return nil, nil
	}

	// Load session information
	var session *authserver.TokenResponse
	if storedSession, ok := w.tokenCache.Load(sessionCookie.Value); !ok {
		zap.L().Debug("Tokens not found in cache.", zap.String("client_name", action.Client.Name()))
		return nil, nil
	} else if session, ok = storedSession.(*authserver.TokenResponse); !ok {
		zap.L().Debug("Tokens not found in cache.", zap.String("client_name", action.Client.Name()))
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
		cookie := generateSessionIDCookie(c, &sessionID, w.ctx.SecureCookies)
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
			Name:   cookieName,
			Value:  "deleted",
			Path:   "/",
			Secure: w.ctx.SecureCookies,
			//TODO: possible to use Expires instead of Max-Age once Istio supports it,
			// see https://github.com/istio/istio/pull/21270
			//Expires:  time.Now().Add(time.Hour * time.Duration(2160)), // 90 days
			MaxAge: 90 * 24 * 60 * 60, // 90 days
		},
	}
	return buildSuccessRedirectResponse(redirectURL, cookies), nil
}

// handleAuthorizationCodeCallback processes a successful OAuth 2.0 callback containing a authorization code
func (w *WebStrategy) handleAuthorizationCodeCallback(code interface{}, request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {

	state, err := w.validateState(action.Client.ID(), request)
	if err != nil {
		zap.L().Info("OIDC callback: could not validate state parameter", zap.Error(err), zap.String("client_name", action.Client.Name()))
		return w.handleErrorCallback(err)
	}

	// Set the redirect URL back to this adapter
	// Some providers require this callback to be the same as the one used for /autorization (handleAuthorizationCodeFlow)
	redirectURL := client.CallbackURLForTarget(action.Client, request.Scheme, request.Host, request.Path)

	// Exchange authorization grant code for tokens
	response, err := action.Client.ExchangeGrantCode(code.(string), redirectURL)
	if err != nil {
		zap.L().Info("OIDC callback: Could not retrieve tokens", zap.Error(err),
			zap.String("client_name", action.Client.Name()), zap.String("redirect_uri", redirectURL))
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

	cookie := generateSessionIDCookie(action.Client, nil, w.ctx.SecureCookies)
	w.tokenCache.Store(cookie.Value, response)

	zap.L().Debug("OIDC callback: created new active session: ", zap.String("session_id", cookie.Value), zap.String("client_name", action.Client.Name()))

	// redirect to the original URL (as specified in the state)
	redirectURL = state.OriginalURL

	// overwrite redirect URL if requested by the action
	if action.RedirectUri != "" {
		redirectURL = action.RedirectUri
	}

	return buildSuccessRedirectResponse(redirectURL, []*http.Cookie{cookie}), nil
}

// handleAuthorizationCodeFlow initiates an OAuth 2.0 / OIDC authorization_code grant flow.
func (w *WebStrategy) handleAuthorizationCodeFlow(request *authnz.RequestMsg, action *engine.Action) (*authnz.HandleAuthnZResponse, error) {
	// set the redirect URL back to this adapter
	redirectURL := client.CallbackURLForTarget(action.Client, request.Scheme, request.Host, request.Path)

	// build and store the OIDC state with the original URL
	originalRequestURL := buildRequestURL(request)
	state, err := w.buildStateParam(action.Client.ID(), originalRequestURL)
	if err != nil {
		zap.L().Info("Could not generate state parameter", zap.Error(err), zap.String("client_name", action.Client.Name()))
		return nil, err
	}
	zap.S().Debugf("Initiating redirect to identity provider using redirect URL: %s", redirectURL)
	return &authnz.HandleAuthnZResponse{
		Result: &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(rpc.UNAUTHENTICATED), // Response tells Mixer to reject request
				Message: "Redirecting to identity provider",
				Details: []*types.Any{status.PackErrorDetail(&policy.DirectHttpResponse{
					Code: policy.Found, // Response Mixer remaps on request
					Headers: map[string]string{
						location: generateAuthorizationURL(action.Client, redirectURL, state),
					},
				})},
			},
		},
	}, nil
}

// getEncryptionSecret retrieves the secret (used to encrypt/decrypt the state) in a
// thread safe manner.
func (w *WebStrategy) getEncryptionSecret() (Encryptor, error) {
	// Allow all threads to check if instance already exists
	if w.encrpytor != nil {
		return w.encrpytor, nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	// Once this thread has the lock check again to see if it had been set while waiting
	if w.encrpytor != nil {
		return w.encrpytor, nil
	}

	// We need to generate a new key set
	sc, err := w.getOrGenerateEncryptionSecret()
	return sc, err
}

// getOrGenerateEncryptionSecret returns the encryptor based on the pre-configured secret
// or it generates a new secret if none has been pre-configured
func (w *WebStrategy) getOrGenerateEncryptionSecret() (Encryptor, error) {
	var secret interface{}
	// Check if key set was already configured. This should occur during helm install
	secret, err := networking.Retry(3, 1, func() (interface{}, error) {
		return w.kubeClient.CoreV1().Secrets(defaultNamespace).Get(defaultKeySecret, metav1.GetOptions{})
	})

	if err != nil {
		zap.S().Infof("Secret %v not found: %v. Another will be generated.", defaultKeySecret, err)
		secret, err = w.generateKeySecret(w.ctx.HashKeySize.Value, w.ctx.BlockKeySize.Value)
		if err != nil {
			zap.L().Info("Failed to generate secret", zap.Error(err))
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

// encryptState encodes and encrypts OidcState
func (w *WebStrategy) encryptState(clientID string, state *OidcState) (string, error) {
	// encode the struct
	data, err := bson.Marshal(&state)
	if err != nil {
		zap.L().Warn("Could not marshal the state object", zap.Error(err))
		return "", err
	}

	sc, err := w.getEncryptionSecret()
	if err != nil {
		zap.L().Warn("Could not get encryptor", zap.Error(err))
		return "", err
	}

	// create the cookie
	if encoded, err := sc.Encode(clientID, data); err == nil {
		return encoded, nil
	} else {
		zap.S().Error("Error encoding state", zap.Error(err), zap.Int("len", len(encoded)))
		return "", err
	}
}

// decryptAndValidateState decrypts and decodes the state string, performs basic validation
// and returns the parsed OidcState
func (w *WebStrategy) decryptAndValidateState(clientID string, encryptedState string) *OidcState {
	if encryptedState == "" {
		zap.L().Debug("Empty encoded state string")
		return nil
	}
	sc, err := w.getEncryptionSecret()
	if err != nil {
		zap.L().Debug("Error getting encryptor", zap.Error(err))
		return nil
	}
	value := []byte{}
	if err := sc.Decode(clientID, encryptedState, &value); err != nil {
		zap.L().Debug("Could not decode encrypted state:", zap.Error(err))
		return nil
	}
	cookieObj := OidcState{}
	if err := bson.Unmarshal(value, &cookieObj); err != nil {
		zap.L().Debug("Could not unmarshal the state object:", zap.Error(err))
		return nil
	}
	if cookieObj.Expiration.Before(time.Now()) {
		zap.S().Debug("State parameter has expired: %v - %v", cookieObj.Expiration, time.Now())
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

// buildState param creates encrypted string holding the action metadata to pass to the OIDC provider as the state
func (w *WebStrategy) buildStateParam(clientID, originalURL string) (string, error) {
	encState, err := w.encryptState(clientID, &OidcState{
		OriginalURL: originalURL,
		Expiration:  time.Now().Add(10 * time.Minute),
	})
	return encState, err
}

// validateState ensures the callback request state parameter matches the state stored in an encrypted session cookie
// Follows from OAuth 2.0 specification https://tools.ietf.org/html/rfc6749#section-4.1.1
func (w *WebStrategy) validateState(clientID string, request *authnz.RequestMsg) (*OidcState, error) {
	// Ensure state is returned on request from identity provider
	if request.Params.State == "" {
		stateError := errors.New("state parameter not provided")
		zap.L().Info("OIDC callback: missing state parameter from identity provider")
		return nil, stateError
	}

	// Unescape state parameter
	encryptedState, err := url.QueryUnescape(request.Params.State)
	if err != nil {
		stateError := errors.New("bad state parameter")
		zap.L().Info("OIDC callback: bad state parameter", zap.String("state", request.Params.State))
		return nil, stateError
	}

	// Parse encrypted state cookie
	state := w.decryptAndValidateState(clientID, encryptedState)

	// Ensure state cookie is returned
	if state == nil {
		stateError := errors.New("invalid state parameter")
		zap.L().Info("OIDC callback: state parameter invalid or malformed")
		return nil, stateError
	}

	zap.L().Debug("OIDC callback: validated state parameter")

	return state, nil
}

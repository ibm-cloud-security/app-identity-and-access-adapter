package webstrategy

import (
	"errors"
	"math/rand"
	"net/http"
	"net/url"
	"time"
	"unsafe"

	"go.uber.org/zap"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

// randString generates a random string of the given size
func randString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

// generateAuthorizationURL builds the /authorization request that begins an OAuth 2.0 / OIDC flow
func generateAuthorizationURL(c client.Client, redirectURI string, state string) string {
	server := c.AuthorizationServer()
	if server == nil {
		zap.L().Warn("Authorization server has not been configured for client", zap.Error(errors.New("authorization server has not been configured")), zap.String("client_name", c.Name()))
		return ""
	}
	baseUrl, err := url.Parse(server.AuthorizationEndpoint())
	if err != nil {
		zap.L().Warn("Malformed Authorization URL", zap.Error(err))
		return ""
	}

	// Prepare Query Parameters
	params := url.Values{
		"client_id":     {c.ID()},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile email"},
		"state":         {state},
	}

	// Add Query Parameters to the URL
	baseUrl.RawQuery = params.Encode() // Escape Query Parameters

	return baseUrl.String()
}

// buildRequestURL constructs the original url from the request object
func buildRequestURL(action *authnz.RequestMsg) string {
	return action.Scheme + "://" + action.Host + action.Path
}

// buildTokenCookieName constructs the cookie name
func buildTokenCookieName(base string, c client.Client) string {
	return base + "-" + c.ID()
}

// generateSessionIDCookie creates a new sessionId cookie
// if the provided value is empty and new id is randomly generated
func generateSessionIDCookie(c client.Client, value *string) *http.Cookie {
	var v = randString(15)
	if value != nil {
		v = *value
	}
	return &http.Cookie{
		Name:     buildTokenCookieName(sessionCookie, c),
		Value:    v,
		Path:     "/",
		Secure:   false, // TODO: replace on release
		HttpOnly: false,
		Expires:  time.Now().Add(time.Hour * time.Duration(2160)), // 90 days
	}
}

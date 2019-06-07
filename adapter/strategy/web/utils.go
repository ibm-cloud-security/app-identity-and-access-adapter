package webstrategy

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/client"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"go.uber.org/zap"
	"math/rand"
	"net/url"
	"time"
	"unsafe"
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
func generateAuthorizationURL(c client.Client, redirectURI string) string {
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
	params.Add("scope", "openid profile email")
	params.Add("state", "randomly_generated_state")

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

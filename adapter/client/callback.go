package client

import (
	"path"
	"regexp"
	"strings"
)

var regexpURL = regexp.MustCompile(`(https?)://([^/]+)(/?.*)`)

func callbackDefinitionForClient(c Client) string {
	callbackDef := ""

	// also support empty clients (for tests without a valid client, using default callbackEndpoint)
	if c != nil {
		callbackDef = c.Callback()
	}

	if callbackDef == "" {
		// if the callback is empty for the client, use the original behavior:
		// /oidc/callback is simply appended to the original path, resulting in many different callback URLs
		callbackDef = "oidc/callback"
	}
	return callbackDef
}

// CallbackURLForTarget returns the absolute URL to which IdP should redirect after authenticating the user.
// This is the speckial URL which is expected to be handled by the adapter under the provided Client configuration.
func CallbackURLForTarget(c Client, requestScheme, requestHost, requestPath string) string {
	callbackDef := callbackDefinitionForClient(c)

	if requestPath == "" {
		requestPath = "/"
	}

	if callbackDef[0] == '/' {
		// callback path absolute on the request host
		return requestScheme + "://" + requestHost + callbackDef
	}

	m := regexpURL.FindStringSubmatch(callbackDef)
	if len(m) > 1 {
		// callback is full URL
		return callbackDef
	}

	// callback path relative to the target path
	if strings.HasSuffix(requestPath, callbackDef) {
		// relative callback path already appended, do not append twice
		// this can happen if this function is called in the actual callback handler
		// (happens after /authorize OIDC provider URL redirects back and we call OIDC provider API again)
		callbackDef = ""
	}
	return requestScheme + "://" + requestHost + path.Join(requestPath, callbackDef)
}

// IsCallbackRequest returns true if the provided request should be handled by the adapter as part of the auth flow
func IsCallbackRequest(c Client, requestScheme, requestHost, requestPath string) bool {
	callbackDef := callbackDefinitionForClient(c)

	if requestPath == "" {
		requestPath = "/"
	}

	if callbackDef[0] == '/' {
		// callback path absolute on the request host
		return strings.HasPrefix(requestPath, callbackDef)
	}

	m := regexpURL.FindStringSubmatch(callbackDef)
	if len(m) == 4 {
		// callback is full URL, compare parts (case-insensitive just in case)
		return strings.EqualFold(m[1], requestScheme) &&
			strings.EqualFold(m[2], requestHost) &&
			strings.EqualFold(m[3], requestPath)
	}

	// callback path relative to the target path, thus ending with callbackDef
	return strings.HasSuffix(requestPath, callbackDef)
}

// Package errors contains custom OAuth 2.0 / OIDC error objects
package errors

import (
	"strings"

	"istio.io/api/policy/v1beta1"
)

// HTTP Errors
const (
	BadRequest          = "Bad Request"
	Unauthorized        = "Unauthorized"
	Forbidden           = "Forbidden"
	InternalServerError = "Internal Server Error"
)

// OAuth 2.0 Errors - https://tools.ietf.org/html/rfc6750#section-3.1
const (
	InvalidRequest    = "invalid_request"
	InvalidToken      = "invalid_token"
	InsufficientScope = "insufficient_scope"
)

const (
	ExpiredToken = "Token is expired"
)

// OAuthError - oauth error
type OAuthError struct {
	Msg    string
	Code   string
	Scopes []string
}

// ExpiredTokenError creates a new expired token error
func ExpiredTokenError() *OAuthError {
	return &OAuthError{
		Msg: ExpiredToken,
	}
}

// UnauthorizedHTTPException creates a new invalid token error
func UnauthorizedHTTPException(msg string, scopes []string) *OAuthError {
	return &OAuthError{
		Msg:    msg,
		Code:   InvalidToken,
		Scopes: scopes,
	}
}

// BadRequestHTTPException creates a new invalid request error
func BadRequestHTTPException(msg string) *OAuthError {
	return &OAuthError{
		Msg:    msg,
		Code:   InvalidRequest,
		Scopes: nil,
	}
}

func (o *OAuthError) Error() string {
	return o.Msg
}

// ShortDescription returns the prettified HTTP Errors
func (o *OAuthError) ShortDescription() string {
	switch o.Code {
	case InvalidRequest:
		return BadRequest
	case InvalidToken:
		return Unauthorized
	case InsufficientScope:
		return Forbidden
	default:
		return InternalServerError
	}
}

// ScopeStr returns a scopes as a whitespace separated list
func (o *OAuthError) ScopeStr() string {
	if o.Scopes == nil || len(o.Scopes) == 0 {
		return ""
	}
	return strings.Join(o.Scopes, " ")
}

// HTTPCode returns Istio compliant HTTPStatusCode
func (o *OAuthError) HTTPCode() v1beta1.HttpStatusCode {
	switch o.Code {
	case InvalidRequest:
		return v1beta1.BadRequest
	case InvalidToken:
		return v1beta1.Unauthorized
	case InsufficientScope:
		return v1beta1.Forbidden
	default:
		return v1beta1.InternalServerError
	}
}

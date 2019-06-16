// Package errors contains custom OAuth 2.0 / OIDC error objects
package errors

import (
	"errors"
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
	Code   string   `json:"error"`
	Msg    string   `json:"error_description"`
	URI    string   `json:"error_uri"`
	Scopes []string `json:"scopes"`
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

func (e *OAuthError) Error() string {
	if e.Code == "" && e.Msg == "" {
		return "an error occurred"
	} else if e.Code == "" {
		return e.Msg
	} else if e.Msg == "" {
		return e.Code
	} else {
		return e.Code + ": " + e.Msg
	}
}

// ShortDescription returns the prettified HTTP Errors
func (e *OAuthError) ShortDescription() string {
	switch e.Code {
	case InvalidRequest:
		return BadRequest
	case InvalidToken:
		return Unauthorized
	case InsufficientScope:
		return Forbidden
	default:
		return e.Code
	}
}

// ScopeStr returns a scopes as a whitespace separated list
func (e *OAuthError) ScopeStr() string {
	if e.Scopes == nil || len(e.Scopes) == 0 {
		return ""
	}
	return strings.Join(e.Scopes, " ")
}

// HTTPCode returns Istio compliant HTTPStatusCode
func (e *OAuthError) HTTPCode() v1beta1.HttpStatusCode {
	switch e.Code {
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

// HTTPCode returns Istio compliant HTTPStatusCode
func (e *OAuthError) OK() error {
	if e.Code == "" {
		return errors.New("invalid OAuth 2.0 Error: `error` field does not exist")
	}
	return nil
}

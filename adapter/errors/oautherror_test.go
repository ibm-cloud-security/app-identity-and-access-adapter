package errors

import (
	"github.com/stretchr/testify/assert"
	"istio.io/api/policy/v1beta1"
	"testing"
)

func TestUnathorizedException(t *testing.T) {
	err := UnauthorizedHTTPException("my error message", []string{"scope1", "scope2"})
	assert.Equal(t, InvalidToken, err.Code)
	assert.Equal(t, v1beta1.Unauthorized, err.HTTPCode())
	assert.Equal(t, "my error message", err.Error())
	assert.Equal(t, Unauthorized, err.ShortDescription())
	assert.Equal(t, "scope1 scope2", err.ScopeStr())
}

func TestBadRequestException(t *testing.T) {
	err := BadRequestHTTPException("my error message")
	assert.Equal(t, InvalidRequest, err.Code)
	assert.Equal(t, v1beta1.BadRequest, err.HTTPCode())
	assert.Equal(t, "my error message", err.Error())
	assert.Equal(t, BadRequest, err.ShortDescription())
	assert.Equal(t, "", err.ScopeStr())
}

func TestInsufficientScopeException(t *testing.T) {
	err := &OAuthError{Msg: "my error message", Code: InsufficientScope}
	assert.Equal(t, InsufficientScope, err.Code)
	assert.Equal(t, v1beta1.Forbidden, err.HTTPCode())
	assert.Equal(t, "my error message", err.Error())
	assert.Equal(t, Forbidden, err.ShortDescription())
	assert.Equal(t, "", err.ScopeStr())
}

func TestInternalServerException(t *testing.T) {
	err := &OAuthError{Msg: "my error message", Code: InternalServerError}
	assert.Equal(t, InternalServerError, err.Code)
	assert.Equal(t, v1beta1.InternalServerError, err.HTTPCode())
	assert.Equal(t, "my error message", err.Error())
	assert.Equal(t, InternalServerError, err.ShortDescription())
	assert.Equal(t, "", err.ScopeStr())
}

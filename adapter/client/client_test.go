package client

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthServerNew(t *testing.T) {
	n := New(v1.OidcClientSpec{
		ClientSecret: "secret",
		ClientID:     "id",
		ClientName:   "name",
	}, nil)
	assert.NotNil(t, n)
	assert.Equal(t, "id", n.ID())
	assert.Equal(t, "name", n.Name())
	assert.Equal(t, "secret", n.Secret())
}

package client

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
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
	assert.Nil(t, n.AuthorizationServer())
	res, err := n.ExchangeGrantCode("", "")
	assert.Nil(t, res)
	assert.EqualError(t, err, "invalid client configuration :: missing authorization server")

	c := n.(*remoteClient)
	c.authServer = &fake.AuthServer{}
	res2, err2 := c.ExchangeGrantCode("", "") // MockServer returns nil, nil
	assert.Nil(t, res2)
	assert.Nil(t, err2)

	res3, err3 := c.RefreshToken("")
	assert.Nil(t, res3)
	assert.Nil(t, err3)
}

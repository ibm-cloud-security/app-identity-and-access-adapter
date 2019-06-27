package client

import (
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/fake"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClientNew(t *testing.T) {
	n := New(v1.OidcConfigSpec{
		ClientSecret: "secret",
		ClientID:     "id",
		ClientName:   "name",
	}, nil)
	assert.NotNil(t, n)
	assert.Equal(t, "id", n.ID())
	assert.Equal(t, "name", n.Name())
	assert.Equal(t, "secret", n.Secret())
	assert.Nil(t, n.AuthorizationServer())
}

func TestClientTokens(t *testing.T) {
	c := remoteClient{
		v1.OidcConfigSpec{
			ClientSecret: "secret",
			ClientID:     "id",
			ClientName:   "name",
		},
		nil,
	}

	res, err := c.ExchangeGrantCode("", "")
	assert.Nil(t, res)
	assert.EqualError(t, err, "invalid client configuration :: missing authorization server")

	res2, err2 := c.RefreshToken("") // MockServer returns nil, nil
	assert.Nil(t, res2)
	assert.EqualError(t, err2, "invalid client configuration :: missing authorization server")

	c.authServer = fake.NewAuthServer()
	res3, err3 := c.ExchangeGrantCode("", "")
	assert.Nil(t, res3)
	assert.Nil(t, err3)

	res4, err4 := c.RefreshToken("")
	assert.Nil(t, res4)
	assert.Nil(t, err4)
}

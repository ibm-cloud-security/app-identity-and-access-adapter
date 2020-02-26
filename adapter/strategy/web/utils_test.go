package webstrategy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/client"
	authnz "github.com/ibm-cloud-security/app-identity-and-access-adapter/config/template"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/fake"
)

func TestRandString(t *testing.T) {
	str1 := randString(10)
	str2 := randString(10)
	str3 := randString(4)
	assert.Equal(t, 10, len(str1))
	assert.Equal(t, 10, len(str2))
	assert.Equal(t, 4, len(str3))
	assert.NotEqual(t, str1, str2)
}

func TestGenerateAuthorizationURL(t *testing.T) {
	type testObj struct {
		expected    string
		redirectURI string
		state       string
		c           client.Client
	}
	tests := []testObj{
		{
			c: &fake.Client{},
		},
		{
			expected:    "https://auth.com/authorization?client_id=id&redirect_uri=https%3A%2F%2Fredirect.com&response_type=code&scope=openid+profile+email&state=12345",
			c:           fake.NewClient(nil),
			redirectURI: "https://redirect.com",
			state:       "12345",
		},
	}

	testRunner := func(test testObj) {
		t.Run("Authorization URL", func(t *testing.T) {
			t.Parallel()
			url := generateAuthorizationURL(test.c, test.redirectURI, test.state)
			assert.Equal(t, test.expected, url)
		})
	}

	for _, test := range tests {
		testRunner(test)
	}
}

func TestBuildRequestURL(t *testing.T) {
	inp := &authnz.RequestMsg{
		Scheme: "https",
		Host:   "me.com",
		Path:   "/hello world",
	}
	assert.Equal(t, "https://me.com/hello world", buildRequestURL(inp))
}

func TestTokenCookieName(t *testing.T) {
	assert.Equal(t, "base-string-id", buildTokenCookieName("base-string", fake.NewClient(nil)))
}

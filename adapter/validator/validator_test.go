package validator

import (
	"crypto"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"ibmcloudappid/adapter/client"
	"testing"
)

const (
	testKid = "appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497"
	// Test keys signed with ../test/key.private
	// Expires year: 5148
	testValidToken      = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6OTk5OTk5OTk5OTksImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.aAR5nZ4S5nifq1Y5_CZpO-s0RD8Mqy6Y_4WJCqoMv5ZIu8D6Ski061rC1Y_sNHVJ283c-qANc0TCAXPGse7vDelkGO2kyo67PzzefZMLXWf-bXZsLfKx_Ivoj7caevq7mP3m0_M4hpkKpiP6KTlW5BlpoLTnroje2ZmTIwSeJ_5Fvx7pwmhmATrVG-zYx3wvDUHNVAQJcxpuPL6ngjuS8KhlWeOdp4wpoyk--DwllNOTjR1m-TuICQ9sL_ioDTZmJtXO3w1KKFzN79H35Ia30jIuqaPBd8SiNTZDuDdaZZt1XSfCLC4ovZvkhYfxk97AKNddr75lzMHUHEAk8SIk3w"
	testExpiredToken    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.c8J_IzG8aH4eq2vBrhOAv7v4JrugxwC8rrZCtMNp0qFbshfOWbNlWLzXYsBNBA_mCpbkP9ChH77Vb0iVY3tnjvatOXyd5udPqn5ETwlU6jS9f3OAqM5xgGUc78BgujlHGxsWUK-IvM8yNwHc18mj9iRQpIvKLxjLn2asha6UR9QwWCpuDIjfXy_Fnn65-3s6riVJ9dgJnHtKDRYmmvJCICfZYXdDSMQmQXcjxALNd1uuJIar4dhakfzQoiCVQZf7SXkseWye5ghDCdIU0oGBxuFcMypSd6bCUJrOnZHGOeS_F6OBvNPGn20EqpfnL8nCYr5wTugArmaRy65XI-PccQ"
	testMissingTenant   = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6OTk5OTk5OTk5OTksImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.Ddn_bF2zy-LJU6ktCrUFZTg6l4S_ZPoSsqrRZGYNTEt-yVXo5tvU6lIRRQZXERRiQBHQ5bOTXWn_oWeRLsswtBx4ATU43PJBszC6lOyR2jwY4udMagE7nCgi6N2FJqYzVzX3q_kuEJjIkUOIhoUwvOtDpOJKvRthLdmQc60aK5McQySVaeq-Dqv1kLYM99JyflcgezUmsJllJ5OJdIsAqC9Pbn9ArxyZNWP51fQGbavkey3isnFqb9ENFo7lxcSSfMNhgJlV8DpLaEC1eAvimg0d-PYEM-u7BuTCPTsjbgEnPTTBda2HXwpEl5BAPeSkj90eiwmrgNQHJnkcfJDniw"
	testTokenMissingKid = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.OW6Fcew-uhs38Owh7UhnffKJhoaEj0O_hHiZPZl8_O_LpEn6hPhWI_t8D67FzATlIhRd_B8vfBa8oSOhxKzNV99EmkzQPMaqItoyTfaJIZIQssgXiXbINFx01uILzZF1PxLvDm6xiHax5Dm4lDWizEmPLL6Am9pyZZKqcC84cqwBOWpMFDuZ0XiRX3i9lPCic-rZHcoxYREqwn0p8a2MZV5oeE5f-H8Kq5rr-yFGXaofEnLqs1Wm1T0mMRiH9O2nE7JnYMPTYUhDxSkwDLIeKe9JBRG9JwC5_br9lK5aOTv6Wk1ODqu4t7Qrniz1kaDWQgO2Z_dFjIu6Ny53BGM6Rg"
	testAlternateKid    = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJvdGhlciIsInZlciI6M30.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.Gyan705Sy_HC_1iHSdyBhFepysB4Gf8WeJmxgf-WQeytaZa8dXjv_VdZrTaX-OtVfRPZEn-FGLr-KKRbEad8jl-of-A6fc6U10JBA8zT5tx5yYTBeCWxBOrJAN4bYZIUKdcRX24-iMoyrm1wt3jCuA3Z3fGnncBq4ndwIhVUqpf_hrivcQlhXk9JEYMzwxydYaWI_ZRhQT21lAC8H1DaLwNbMe_0AfBGhyO4Yk3boa68Mhd3uhYFZQ_NIemXa2oXI3R_gWLdM43qrNkBs_7YFEWIa6hI6A3Yyzz95ZbiZv23lFEym_lAFoqkCt9MAcWhitnG1Gg-IWEr_C-uPTNknw"
)

var testProviderConfig = client.ProviderConfig{
	Issuer:      "localhost:6002",
	AuthURL:     "",
	TokenURL:    "",
	JWKSURL:     "",
	UserInfoURL: "",
}
var testConfig = client.Config{
	Name:         "71b34890-a94f-4ef2-a4b6-ce094aa68092",
	ClientID:     "",
	Secret:       "",
	DiscoveryURL: "",
	Type:         client.OIDC,
}

var testClient = client.Client{
	Config:         testConfig,
	ProviderConfig: testProviderConfig,
	KeySet:         &localKeySet{},
}

type localKeySet struct{}

func (k *localKeySet) RetrievePublicKeys() error               { return nil }
func (k *localKeySet) PublicKeys() map[string]crypto.PublicKey { return nil }
func (k *localKeySet) PublicKey(kid string) crypto.PublicKey {
	if kid == testKid {
		keyData, _ := ioutil.ReadFile("../test/key.pub")
		key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)
		return key
	}
	return nil
}

/////// Token Validation ///////

func TestTokenValidation(t *testing.T) {
	var tests = []struct {
		token       string
		expectErr   bool
		expectedMsg string
	}{
		{testValidToken, false, ""},
		{testExpiredToken, true, "Token is expired"},
		{testValidToken + "other", true, "crypto/rsa: verification error"},
		{testMissingTenant, true, "token validation error - expected claim `tenant` to exist"},
		{testTokenMissingKid, true, "token validation error - kid is missing"},
		{testAlternateKid, true, "token validation error - key not found for kid: other"},
		{"p1.p2", true, "token contains an invalid number of segments"},
	}
	v := New()

	for _, e := range tests {
		err := v.Validate(testClient, e.token)
		if err != nil && e.expectErr {
			assert.Equal(t, e.expectedMsg, err.Error())
		} else if err != nil && !e.expectErr {
			assert.Fail(t, "Unexpected error: "+err.Error())
		} else if err == nil && e.expectErr {
			assert.Fail(t, "Expected to receive error: "+e.expectedMsg)
		}
	}
}

/////// Claim Validation //////

func TestClaimValidation(t *testing.T) {
	var tests = []struct {
		claimName   string
		expectErr   bool
		expectedVal string
		expectedMsg string
	}{
		{"tenant", false, "1234", ""},
		{"tenant", true, "12345", "token validation error - expected claim tenant to equal 12345, but found 1234"},
		{"tenant2", true, "", "token validation error - expected claim `tenant2` to exist"},
	}

	var claimMap jwt.MapClaims = make(map[string]interface{})
	claimMap["tenant"] = "1234"

	for _, e := range tests {
		err := validateClaim(e.claimName, e.expectedVal, claimMap)
		if e.expectErr {
			assert.Equal(t, err.Error(), e.expectedMsg)
		} else {
			assert.Nil(t, err)
		}
	}
}

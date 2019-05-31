package validator

import (
	"crypto"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/stretchr/testify/assert"
)

const (
	testKid         = "appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497"
	pathToPublicKey = "../../tests/keys/key.pub"
	// Test keys signed with ../../tests/keyskey.private
	// Expires year: 2160
	validAudStrToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6NTk5OTk5OTk5OSwiYXVkIjoiYzE2OTIwZTMtYTZlYi00YmE1LWIyMWEtZTcyYWZjODZiYWYzIiwic3ViIjoiYzE2OTIwZTMtYTZlYi00YmE1LWIyMWEtZTcyYWZjODZiYWYzIiwiYW1yIjpbImFwcGlkX2NsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1NTYxMzcwNzgsInRlbmFudCI6IjcxYjM0ODkwLWE5NGYtNGVmMi1hNGI2LWNlMDk0YWE2ODA5MiIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCJ9.pHm5jijwP7ERxdCbjBhHf_RHaE5QcCbicteonYln3aU9ck-eiFzwxY-Ze8jTbpieCuoXfYUzitIIHHhcqVws0EyRCL2liYm7Oc1tJgtyH3SfWlpJ-65p4KVusrnGjSF0HfCB4NAbZGpvOY88LhEMr_S99nhPSaZrUkEgm5Pdoda7e91yYlOygs3N98WNF4sU548sS4TttTpeeA-fxqJFVI5lG37NveM-Mm2P1TQmKCfOB6CBm9Eibl4zU8kF22aWZ8kbkVdim303-qxhJhknFapdsHzCa6-cDLUsGNHltG8ACePe4o0C9n4m2Eq8XZ50GcocpwLdkB4XItGzuhHrOg"
	validAudArrToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6NTk5OTk5OTk5OSwiYXVkIjpbImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyJdLCJzdWIiOiJjMTY5MjBlMy1hNmViLTRiYTUtYjIxYS1lNzJhZmM4NmJhZjMiLCJhbXIiOlsiYXBwaWRfY2xpZW50X2NyZWRlbnRpYWxzIl0sImlhdCI6MTU1NjEzNzA3OCwidGVuYW50IjoiNzFiMzQ4OTAtYTk0Zi00ZWYyLWE0YjYtY2UwOTRhYTY4MDkyIiwic2NvcGUiOiJhcHBpZF9kZWZhdWx0In0.czBqkysqXxq0pkqVVUDmFdu_fsd1D0LSttqOSrcGkTao3W6THcR967NUXr1_DAXwzqDhBWp0tIqE6y3P0IdxC_3zM6S8fgv5HYYOqSPYQQLOM7Dy7lyEVwR0U4OVjLHttXjV6vXJsj7ehgUQ4SbXfm8fotEI1T6uwV6eU6vawOA3NPJgEDbBjTMxnpdIV34LgK5iP06aB7acniqO5mJtRggJYhExU_QoXjpqI8s2wimlCtssdOPVIvQ2l_GqpKJr6bk8BQIaw6qIfOvYwrDyGHPTRytt63Sk6hXLq5fPPCmXUzwRvc4ZKzy7YfhIvVsQ8go_XRMZhGcwnj14mJ21ew"
	expiredToken     = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.c8J_IzG8aH4eq2vBrhOAv7v4JrugxwC8rrZCtMNp0qFbshfOWbNlWLzXYsBNBA_mCpbkP9ChH77Vb0iVY3tnjvatOXyd5udPqn5ETwlU6jS9f3OAqM5xgGUc78BgujlHGxsWUK-IvM8yNwHc18mj9iRQpIvKLxjLn2asha6UR9QwWCpuDIjfXy_Fnn65-3s6riVJ9dgJnHtKDRYmmvJCICfZYXdDSMQmQXcjxALNd1uuJIar4dhakfzQoiCVQZf7SXkseWye5ghDCdIU0oGBxuFcMypSd6bCUJrOnZHGOeS_F6OBvNPGn20EqpfnL8nCYr5wTugArmaRy65XI-PccQ"
	noKidToken       = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.OW6Fcew-uhs38Owh7UhnffKJhoaEj0O_hHiZPZl8_O_LpEn6hPhWI_t8D67FzATlIhRd_B8vfBa8oSOhxKzNV99EmkzQPMaqItoyTfaJIZIQssgXiXbINFx01uILzZF1PxLvDm6xiHax5Dm4lDWizEmPLL6Am9pyZZKqcC84cqwBOWpMFDuZ0XiRX3i9lPCic-rZHcoxYREqwn0p8a2MZV5oeE5f-H8Kq5rr-yFGXaofEnLqs1Wm1T0mMRiH9O2nE7JnYMPTYUhDxSkwDLIeKe9JBRG9JwC5_br9lK5aOTv6Wk1ODqu4t7Qrniz1kaDWQgO2Z_dFjIu6Ny53BGM6Rg"
	diffKidToken     = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJvdGhlciIsInZlciI6M30.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.Gyan705Sy_HC_1iHSdyBhFepysB4Gf8WeJmxgf-WQeytaZa8dXjv_VdZrTaX-OtVfRPZEn-FGLr-KKRbEad8jl-of-A6fc6U10JBA8zT5tx5yYTBeCWxBOrJAN4bYZIUKdcRX24-iMoyrm1wt3jCuA3Z3fGnncBq4ndwIhVUqpf_hrivcQlhXk9JEYMzwxydYaWI_ZRhQT21lAC8H1DaLwNbMe_0AfBGhyO4Yk3boa68Mhd3uhYFZQ_NIemXa2oXI3R_gWLdM43qrNkBs_7YFEWIa6hI6A3Yyzz95ZbiZv23lFEym_lAFoqkCt9MAcWhitnG1Gg-IWEr_C-uPTNknw"
)

////// Mocks /////

type localKeySet struct{ url string }

func (k *localKeySet) PublicKeyURL() string { return k.url }
func (k *localKeySet) PublicKey(kid string) crypto.PublicKey {
	if kid == testKid && k.url != "ignore" {
		keyData, _ := ioutil.ReadFile(pathToPublicKey)
		key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)
		return key
	}
	return nil
}

var testKeySet = &localKeySet{url: "https://keys.com/publickeys"}

var emptyRule = []policy.Rule{}

/////// Token Validation ///////

func TestTokenValidation(t *testing.T) {
	var tests = []struct {
		token string
		err   error
		jwks  keyset.KeySet
		rules []policy.Rule
	}{
		{validAudArrToken, errors.New("Internal Server Error"), nil, emptyRule},

		{validAudStrToken, nil, testKeySet, emptyRule},
		{validAudArrToken, nil, testKeySet, emptyRule},
		{expiredToken, errors.New("Token is expired"), testKeySet, emptyRule},
		{validAudArrToken + "other", errors.New("crypto/rsa: verification error"), testKeySet, emptyRule},
		{noKidToken, errors.New("token validation error - kid is missing"), testKeySet, emptyRule},
		{diffKidToken, errors.New("token validation error - key not found for kid: other"), testKeySet, emptyRule},
		{"p1.p2", errors.New("token contains an invalid number of segments"), testKeySet, emptyRule},
	}
	v := New()

	for _, e := range tests {
		err := v.Validate(e.token, e.jwks, e.rules)
		if e.err != nil {
			assert.EqualError(t, err, e.err.Error())
		} else {
			assert.Nil(t, err)
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

func TestValidateClaims(t *testing.T) {
	err := validateClaims(nil, nil)
	assert.Equal(t, err.Error(), "Internal Server Error")
}

func TestGetClaims(t *testing.T) {
	claims, err := getClaims(nil)
	assert.Nil(t, claims)
	assert.NotNil(t, err)
}

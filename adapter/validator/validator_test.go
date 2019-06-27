package validator

import (
	"context"
	"crypto"
	e "errors"
	"io/ioutil"

	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/networking"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/policy"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/authserver/keyset"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/errors"
)

const (
	testAud         = "c16920e3-a6eb-4ba5-b21a-e72afc86baf3"
	testKid         = "appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497"
	pathToPublicKey = "../../tests/keys/key.pub"
	validToken      = "valid"
	inValidToken    = "invalid"
	userinfo        = "/userinfo"
	// Test keys signed with ../../tests/keys/key.private
	// Expires year: 2160
	validAudStrToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6NTk5OTk5OTk5OSwiYXVkIjoiYzE2OTIwZTMtYTZlYi00YmE1LWIyMWEtZTcyYWZjODZiYWYzIiwic3ViIjoiYzE2OTIwZTMtYTZlYi00YmE1LWIyMWEtZTcyYWZjODZiYWYzIiwiYW1yIjpbImFwcGlkX2NsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1NTYxMzcwNzgsInRlbmFudCI6IjcxYjM0ODkwLWE5NGYtNGVmMi1hNGI2LWNlMDk0YWE2ODA5MiIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCIsImFycl9pbnQiOlsxLDIsMyw0LDVdLCJhcnJfYm9vbCI6W3RydWVdLCJib29sIjp0cnVlLCJpbnQiOjEwMCwib2JqIjp7InN0ciI6ImhlbGxvIiwiYXJyYXlfc3RyIjpbIjEiLCIyIl0sIm9iaiI6eyJzdHIiOiJ3b3JsZCJ9fX0.lBU2kpcU78aq7VDi3N0AboUjFLs65KH4SJOjG63m7HAnb86QtNc7PiA_YOqo9uCXWUdKv9tGvCGxeEx0rvFW_-LGUO0n88avM2HxBDFSI9OL7lFySSdTsBe7okPWdUuruIOGfbWVDSDDEdkwlJ0DLnFOAUqYhQW1dV8TtyqbYb2xyDv_jCDhIz2uE7dTqQBHa_uZFy_pOsiWAZb83xjoMCoV03bP2c3ZzpFFToF3IJuldo4bCr1XYJAlTp7P6hzG4ELhQp5f5pNGLtTWZaxicx5Qs5Mp0fUtdLjYRPmzuhmOT01qyJBRHDnil3bQ_W1lsHgv3oVdLs_AGn3_D8WF1A"
	validAudArrToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6NTk5OTk5OTk5OSwiYXVkIjpbImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyJdLCJzdWIiOiJjMTY5MjBlMy1hNmViLTRiYTUtYjIxYS1lNzJhZmM4NmJhZjMiLCJhbXIiOlsiYXBwaWRfY2xpZW50X2NyZWRlbnRpYWxzIl0sImlhdCI6MTU1NjEzNzA3OCwidGVuYW50IjoiNzFiMzQ4OTAtYTk0Zi00ZWYyLWE0YjYtY2UwOTRhYTY4MDkyIiwic2NvcGUiOiJhcHBpZF9kZWZhdWx0In0.czBqkysqXxq0pkqVVUDmFdu_fsd1D0LSttqOSrcGkTao3W6THcR967NUXr1_DAXwzqDhBWp0tIqE6y3P0IdxC_3zM6S8fgv5HYYOqSPYQQLOM7Dy7lyEVwR0U4OVjLHttXjV6vXJsj7ehgUQ4SbXfm8fotEI1T6uwV6eU6vawOA3NPJgEDbBjTMxnpdIV34LgK5iP06aB7acniqO5mJtRggJYhExU_QoXjpqI8s2wimlCtssdOPVIvQ2l_GqpKJr6bk8BQIaw6qIfOvYwrDyGHPTRytt63Sk6hXLq5fPPCmXUzwRvc4ZKzy7YfhIvVsQ8go_XRMZhGcwnj14mJ21ew"
	expiredToken     = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC03MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTItMjAxOC0wOC0wMlQxMTo1MzozNi40OTciLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.c8J_IzG8aH4eq2vBrhOAv7v4JrugxwC8rrZCtMNp0qFbshfOWbNlWLzXYsBNBA_mCpbkP9ChH77Vb0iVY3tnjvatOXyd5udPqn5ETwlU6jS9f3OAqM5xgGUc78BgujlHGxsWUK-IvM8yNwHc18mj9iRQpIvKLxjLn2asha6UR9QwWCpuDIjfXy_Fnn65-3s6riVJ9dgJnHtKDRYmmvJCICfZYXdDSMQmQXcjxALNd1uuJIar4dhakfzQoiCVQZf7SXkseWye5ghDCdIU0oGBxuFcMypSd6bCUJrOnZHGOeS_F6OBvNPGn20EqpfnL8nCYr5wTugArmaRy65XI-PccQ"
	noKidToken       = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJ2ZXIiOjN9.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.OW6Fcew-uhs38Owh7UhnffKJhoaEj0O_hHiZPZl8_O_LpEn6hPhWI_t8D67FzATlIhRd_B8vfBa8oSOhxKzNV99EmkzQPMaqItoyTfaJIZIQssgXiXbINFx01uILzZF1PxLvDm6xiHax5Dm4lDWizEmPLL6Am9pyZZKqcC84cqwBOWpMFDuZ0XiRX3i9lPCic-rZHcoxYREqwn0p8a2MZV5oeE5f-H8Kq5rr-yFGXaofEnLqs1Wm1T0mMRiH9O2nE7JnYMPTYUhDxSkwDLIeKe9JBRG9JwC5_br9lK5aOTv6Wk1ODqu4t7Qrniz1kaDWQgO2Z_dFjIu6Ny53BGM6Rg"
	diffKidToken     = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJvdGhlciIsInZlciI6M30.eyJpc3MiOiJsb2NhbGhvc3Q6NjAwMiIsImV4cCI6MTAwMDAwMDAsImF1ZCI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsInN1YiI6ImMxNjkyMGUzLWE2ZWItNGJhNS1iMjFhLWU3MmFmYzg2YmFmMyIsImFtciI6WyJhcHBpZF9jbGllbnRfY3JlZGVudGlhbHMiXSwiaWF0IjoxNTU2MTM3MDc4LCJ0ZW5hbnQiOiI3MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJzY29wZSI6ImFwcGlkX2RlZmF1bHQifQ.Gyan705Sy_HC_1iHSdyBhFepysB4Gf8WeJmxgf-WQeytaZa8dXjv_VdZrTaX-OtVfRPZEn-FGLr-KKRbEad8jl-of-A6fc6U10JBA8zT5tx5yYTBeCWxBOrJAN4bYZIUKdcRX24-iMoyrm1wt3jCuA3Z3fGnncBq4ndwIhVUqpf_hrivcQlhXk9JEYMzwxydYaWI_ZRhQT21lAC8H1DaLwNbMe_0AfBGhyO4Yk3boa68Mhd3uhYFZQ_NIemXa2oXI3R_gWLdM43qrNkBs_7YFEWIa6hI6A3Yyzz95ZbiZv23lFEym_lAFoqkCt9MAcWhitnG1Gg-IWEr_C-uPTNknw"
)

// //// Mocks /////

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

var emptyRule = []v1.Rule{}

// ///// Token Validation ///////

func TestTokenValidation(t *testing.T) {
	var tests = []struct {
		token     string
		tokenType Token
		err       *errors.OAuthError
		jwks      keyset.KeySet
		rules     []v1.Rule
	}{
		{"", Access, &errors.OAuthError{Code: errors.InvalidToken}, nil, emptyRule},
		{"token", Access, &errors.OAuthError{Code: errors.InvalidToken}, testKeySet, emptyRule},
		{"p1.p2.p3", Access, &errors.OAuthError{Code: errors.InvalidToken}, testKeySet, emptyRule},
		{"token", ID, &errors.OAuthError{Code: errors.InvalidToken}, testKeySet, emptyRule},
		{validAudArrToken, ID, &errors.OAuthError{Msg: errors.InternalServerError}, nil, emptyRule},
		{validAudStrToken, ID, nil, testKeySet, emptyRule},
		{validAudArrToken, ID, nil, testKeySet, emptyRule},
		{expiredToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "Token is expired"}, testKeySet, emptyRule},
		{validAudArrToken + "other", ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "crypto/rsa: verification error"}, testKeySet, emptyRule},
		{noKidToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - kid is missing"}, testKeySet, emptyRule},
		{diffKidToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - key not found :: other"}, testKeySet, emptyRule},
		{"p1.p2", ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token contains an invalid number of segments"}, testKeySet, emptyRule},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "iss",
				Values: []string{"localhost:6002"},
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "aud",
				Values: []string{testAud},
			},
		}},
		{validAudArrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "aud",
				Values: []string{testAud},
			},
		}},
		{validAudArrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `aud` to match all of: [another audience]"}, testKeySet, []v1.Rule{
			{
				Claim:  "aud",
				Values: []string{"another audience"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `iss` to match all of: [another Values]"}, testKeySet, []v1.Rule{
			{
				Claim:  "iss",
				Values: []string{"another Values"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `aud` to not match any of: [" + testAud + " 2]"}, testKeySet, []v1.Rule{
			{
				Claim:  "aud",
				Match:  "NOT",
				Values: []string{testAud, "2"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "arr_int",
				Match:  "ANY",
				Values: []string{"1", "2", "3"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `scope` to not match any of: [appid_default]", Scopes: []string{"appid_default"}}, testKeySet, []v1.Rule{
			{
				Claim:  "scope",
				Match:  "NOT",
				Values: []string{"appid_default"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `custom_claim` does not exist - rule requires: [custom]", Scopes: nil}, testKeySet, []v1.Rule{
			{
				Claim:  "custom_claim",
				Match:  "ALL",
				Values: []string{"custom"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `scope` to not match any of: [appid_default]", Scopes: []string{"appid_default"}}, testKeySet, []v1.Rule{
			{
				Claim:  "aud",
				Values: []string{testAud},
				Source: ID.String(),
			},
			{
				Claim:  "scope",
				Match:  "NOT",
				Values: []string{"appid_default"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "int",
				Values: []string{"100"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `int` to match all of: [1]", Scopes: nil}, testKeySet, []v1.Rule{
			{
				Claim:  "int",
				Values: []string{"1"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "bool",
				Values: []string{"true"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `arr_bool` to match all of: [false]", Scopes: nil}, testKeySet, []v1.Rule{
			{
				Claim:  "arr_bool",
				Values: []string{"false"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "arr_bool",
				Values: []string{"true", "true"},
				Source: ID.String(),
			},
		}}, // Nested
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "obj.str",
				Values: []string{"hello"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "obj.array_str",
				Values: []string{"1", "2"},
				Source: ID.String(),
			},
		}},
		{validAudStrToken, ID, nil, testKeySet, []v1.Rule{
			{
				Claim:  "obj.array_str",
				Values: []string{"1"},
				Source: ID.String(),
				Match:  "ANY",
			},
		}},
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `obj.str` to match all of: [not]"}, testKeySet, []v1.Rule{
			{
				Claim:  "obj.str",
				Values: []string{"not"},
				Source: ID.String(),
			},
		}}, // Unknown Types
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "claim is not of a supported type: map[string]interface {}"}, testKeySet, []v1.Rule{
			{
				Claim:  "obj",
				Values: []string{"{}"},
				Source: ID.String(),
			},
		}}, // Invalid nesting
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `bool.next` does not exist - rule requires: [true]"}, testKeySet, []v1.Rule{
			{
				Claim:  "bool.next",
				Values: []string{"true"},
				Source: ID.String(),
			},
		}},
		// Empty claim
		{validAudStrToken, ID, &errors.OAuthError{Code: errors.InvalidToken, Msg: "token validation error - expected claim `` does not exist - rule requires: []"}, testKeySet, []v1.Rule{
			{
				Claim:  "",
				Values: []string{""},
				Source: ID.String(),
			},
		}},
	}
	for _, e := range tests {
		t.Run("Validate", func(st *testing.T) {
			runTest := func(v TokenValidator) {
				oaErr := v.Validate(e.token, e.tokenType, e.jwks, e.rules, userinfo)
				if e.err != nil {
					if e.err.Code != "" {
						assert.Equal(st, e.err.Code, oaErr.Code)
					}
					if e.err.Msg != "" {
						assert.Equal(st, e.err.Msg, oaErr.Msg)
					}
					if e.err.Scopes != nil {
						assert.ElementsMatch(st, e.err.Scopes, oaErr.Scopes)
					}
				} else {
					assert.Nil(st, oaErr)
				}
			}
			runTest(NewTokenValidator(policy.OIDC))
			runTest(NewTokenValidator(policy.JWT))
		})
	}
}

// ///// Claim Validation //////

func TestClaimValidation(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		rule      v1.Rule
		expectErr error
	}{ // Strings
		{v1.Rule{
			Claim:  "string",
			Match:  "ALL",
			Values: []string{"1"},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "string",
			Match:  "ALL",
			Values: []string{},
		},
			e.New("token validation error - expected claim `string` to match all of: [], but is empty"),
		},
		{v1.Rule{
			Claim:  "string",
			Match:  "ALL",
			Values: []string{"6"},
		},
			e.New("token validation error - expected claim `string` to match all of: [6]"),
		},
		{v1.Rule{
			Claim:  "string",
			Match:  "ANY",
			Values: []string{},
		},
			e.New("token validation error - expected claim `string` to match one of: []"),
		},
		// String arrays
		{v1.Rule{
			Claim:  "string_arr",
			Match:  "ALL",
			Values: []string{"1", "2", "3", "4"},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "string_arr",
			Match:  "ANY",
			Values: []string{"1"},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "string_arr",
			Match:  "NOT",
			Values: []string{},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "string_arr",
			Match:  "ANY",
			Values: []string{"6", ""},
		},
			e.New("token validation error - expected claim `string_arr` to match one of: [6 ]"),
		}, // Arrays of strings
		{v1.Rule{
			Claim:  "arr_string",
			Match:  "ALL",
			Values: []string{"1", "2", "3", "4"},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "arr_string",
			Match:  "ANY",
			Values: []string{"1", "5", "6", "7"},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "arr_string",
			Match:  "NOT",
			Values: []string{"7", "8", "9", "10"},
		},
			nil,
		},
		{v1.Rule{
			Claim:  "arr_string",
			Match:  "NOT",
			Values: []string{"7", "1"},
		},
			e.New("token validation error - expected claim `arr_string` to not match any of: [7 1]"),
		},
		{v1.Rule{
			Claim:  "arr_string",
			Match:  "ALL",
			Values: []string{"7", "1"},
		},
			e.New("token validation error - expected claim `arr_string` to match all of: [7 1]"),
		},
		{v1.Rule{
			Claim:  "arr_string",
			Match:  "ANY",
			Values: []string{"7", "8"},
		},
			e.New("token validation error - expected claim `arr_string` to match one of: [7 8]"),
		},
	}

	var claimMap jwt.MapClaims = make(map[string]interface{})
	claimMap["string"] = "1"
	claimMap["arr_string"] = []interface{}{"1", "2", "3", "4", "5"}
	claimMap["string_arr"] = "1 2 3 4 5"
	claimMap["int"] = 1
	claimMap["arr_int"] = []interface{}{1, 2, 3, 4, 5}
	claimMap["bool"] = true
	claimMap["bool_int"] = []interface{}{true}
	var nestedMap jwt.MapClaims = make(map[string]interface{})
	nestedMap["value"] = "1 2 3 4 5"
	claimMap["nested"] = nestedMap

	for _, e := range tests {
		test := e
		t.Run("Validate", func(st *testing.T) {
			// st.Parallel()
			err := checkAccessPolicy(test.rule, claimMap)
			if test.expectErr != nil {
				assert.EqualError(st, err, test.expectErr.Error())
			} else {
				assert.Nil(st, err)
			}
		})
	}
}

func TestValidateClaims(t *testing.T) {
	err := validateClaims(nil, Access, nil)
	assert.Equal(t, "Internal Server Error", err.Error())

	err = validateClaims(&jwt.Token{}, Access, []v1.Rule{})
	assert.Equal(t, err.Msg, errors.InvalidToken)
}

func TestGetClaims(t *testing.T) {
	claims, err := getClaims(nil)
	assert.Nil(t, claims)
	assert.NotNil(t, err)

}

func TestValidateAccessTokenString(t *testing.T) {
	var tests = []struct {
		tokenUrl string
		tokenStr string
		rules    []v1.Rule
		err      *errors.OAuthError
	}{
		{
			tokenUrl: userinfo,
			tokenStr: validToken,
			rules:    emptyRule,
			err:      nil,
		},
		{
			tokenUrl: userinfo,
			tokenStr: inValidToken,
			rules:    emptyRule,
			err:      errors.UnauthorizedHTTPException("Unauthorized - invalid token", nil),
		},
		{
			tokenUrl: userinfo,
			tokenStr: validToken,
			rules: []v1.Rule{
				{
					Claim:  "int",
					Values: []string{"100"},
					Source: Access.String(),
				},
			},
			err: errors.BadRequestHTTPException("Unauthorized - rules configured for opaque access token"),
		},
	}

	for _, test := range tests {
		t.Run("ValidateAccessTokenString", func(st *testing.T) {
			// Overwrite Http req handler
			h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("Authorization") == "Bearer "+validToken {
					w.WriteHeader(200)
				} else {
					w.WriteHeader(401)
				}
				w.Write([]byte(""))
			})

			// Start a local HTTP server
			_, server := httpClient(h)

			// Server URL
			url := server.URL + test.tokenUrl

			oaErr := validateAccessTokenString(url, test.tokenStr, test.rules)
			if test.err != nil {
				if test.err.Code != "" {
					assert.Equal(st, test.err.Code, oaErr.Code)
				}
				if test.err.Msg != "" {
					assert.Equal(st, test.err.Msg, oaErr.Msg)
				}
				if test.err.Scopes != nil {
					assert.ElementsMatch(st, test.err.Scopes, oaErr.Scopes)
				}
			} else {
				assert.Nil(t, oaErr)
			}

			// cleanup
			server.Close()
		})
	}
}

func TestNewTokenValidator(t *testing.T) {
	tests := []struct {
		tokenType policy.Type
		expected  TokenValidator
	}{
		{
			tokenType: policy.JWT,
			expected:  &JwtTokenValidator{},
		},
		{
			tokenType: policy.OIDC,
			expected:  &OidcTokenValidator{},
		},
		{
			tokenType: policy.NONE,
			expected:  nil,
		},
	}

	for _, test := range tests {
		t.Run("NewTokenValidator", func(st *testing.T) {
			assert.Equal(t, NewTokenValidator(test.tokenType), test.expected)
		})
	}
}

// httpClient mock
func httpClient(handler http.Handler) (*networking.HTTPClient, *httptest.Server) {
	s := httptest.NewServer(handler)

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, s.Listener.Addr().String())
			},
		},
	}

	n := &networking.HTTPClient{
		Client: cli,
	}
	return n, s
}

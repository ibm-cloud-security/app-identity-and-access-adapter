package jwt

import (
	"errors"
	"fmt"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/crd"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"github.com/stretchr/testify/require"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	jwtTemplatePath = "./templates/jwt_policy.yaml"
)

///
// Create a before method to setup a suite before tests execute
//
func before(ctx *framework.Context) error {
	if !utils.Exists("kubectl") {
		return errors.New("missing required executable kubectl")
	}
	if !ctx.OAuthManager.OK() {
		return errors.New("missing oauth / oidc configuration")
	}
	if err := ctx.OAuthManager.ROP("testuser", "password"); err != nil {
		return err
	}
	return nil
}

///
// Create a cleanup method to execute once a suite has completed
//
func after(ctx *framework.Context) error {
	_ = ctx.CRDManager.CleanUp()
	return nil
}

///
// Test main runs before ALL suite methods run
// and begins test execution
//
func TestMain(t *testing.M) {
	framework.
		NewSuite("jwt_e2e_tests", t).
		Setup(before).
		Cleanup(after).
		Run()
}

func TestInvalidJwkURL(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := crd.JWTPolicy{
				Name:      "jwt-name-0",
				NameSpace: "default",
				JwksURL:   "https://test",
				Service: []crd.JWTService{
					{
						"service-test",
						[]string{"/service-test"},
					},
				},
			}

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			if err == nil || !strings.Contains(err.Error(), "jwksUrl in body should match") {
				t.Fail()
			}
		})
}

func TestValidJWTCRD(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := crd.JWTPolicy{
				Name:      "jwt-name-1",
				NameSpace: "default",
				JwksURL:   ctx.OAuthManager.PublicKeysURL(),
				Service: []crd.JWTService{
					{
						"service-test",
						[]string{"/api", "/web"},
					},
					{
						"service-test2",
						[]string{"/api", "/api/2"},
					},
				},
			}

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			if err != nil {
				t.Fail()
			}
		})
}

func TestInvalidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := crd.JWTPolicy{
				Name:      "jwt-name-2",
				NameSpace: "sample-app",
				JwksURL:   ctx.OAuthManager.PublicKeysURL(),
				Service: []crd.JWTService{
					{
						"svc-sample-app",
						[]string{"/api/headers"},
					},
				},
			}

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			if err != nil {
				t.Fail()
				return
			}

			tests := []struct {
				err           string
				authorization string
			}{
				{
					err:           "authorization header not provided",
					authorization: "",
				},
				{
					err:           "authorization header malformed",
					authorization: "Bearer",
				},
				{
					err:           "invalid access token",
					authorization: "Bearer access.token.sig",
				},
				{
					err:           "invalid access token",
					authorization: "Bearer " + *ctx.OAuthManager.Tokens.AccessToken + "123",
				},
			}

			for _, test := range tests {
				time.Sleep(1 * time.Second) // Give a second to sync adapter
				t.Run("Request", func(st *testing.T) {
					st.Parallel()
					res, err := ctx.SendAuthRequest("GET", "/api/headers", test.authorization)
					if err != nil {
						st.Fail()
						return
					}
					require.Equal(st, http.StatusUnauthorized, res.StatusCode)
					validateResponseCookie(st, test.err, res.Header)
				})
			}
		})
}

/*
TODO: Uncomment when deletion is fixed
func TestDeletePolicy(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := crd.JWTPolicy{
				Name:      "jwt-name-5",
				NameSpace: "sample-app",
				JwksURL:   ctx.OAuthManager.PublicKeysURL(),
				Service: []crd.JWTService{
					{
						"svc-sample-app",
						[]string{"/api/headers/header1"},
					},
				},
			}

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			if err != nil {
				t.Fail()
				return
			}

			time.Sleep(3 * time.Second)

			res, err := ctx.SendAuthRequest("GET", "/api/headers/header1", "")
			if err != nil {
				t.Fail()
				return
			}
			require.Equal(t, http.StatusUnauthorized, res.StatusCode)

			err = ctx.CRDManager.DeleteCRD(&policy)
			if err != nil {
				t.Fail()
				return
			}

			time.Sleep(3 * time.Second)

			res, err = ctx.SendAuthRequest("GET", "/api/headers/header1", "")
			if err != nil {
				t.Fail()
				return
			}
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
}*/

func TestValidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := crd.JWTPolicy{
				Name:      "jwt-name-3",
				NameSpace: "sample-app",
				JwksURL:   ctx.OAuthManager.PublicKeysURL(),
				Service: []crd.JWTService{
					{
						"svc-sample-app",
						[]string{"/api/headers"},
					},
				},
			}

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			if err != nil {
				t.Fail()
				fmt.Println(err)
				return
			}

			tests := []struct {
				authorization string
			}{
				{
					authorization: "Bearer " + *ctx.OAuthManager.Tokens.AccessToken,
				},
				{
					authorization: "Bearer " + *ctx.OAuthManager.Tokens.AccessToken + " " + *ctx.OAuthManager.Tokens.IdentityToken,
				},
			}

			for _, test := range tests {
				time.Sleep(1 * time.Second) // Give a second to sync adapter
				t.Run("Request", func(st *testing.T) {
					st.Parallel()
					res, err := ctx.SendAuthRequest("GET", "/api/headers", test.authorization)
					if err != nil {
						st.Fail()
						return
					}
					require.Equal(st, http.StatusOK, res.StatusCode)
				})
			}
		})
}

func validateResponseCookie(t *testing.T, message string, headers http.Header) {
	if val, ok := headers["Www-Authenticate"]; ok {
		if strings.Contains(val[0], message) {
			return

		}
		fmt.Printf("%s | %s\n", val[0], message)
	}
	t.Fail()
}

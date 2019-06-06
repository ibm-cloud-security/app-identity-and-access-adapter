package jwt

import (
	"errors"
	"fmt"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	if !ctx.AppIDManager.OK() {
		return errors.New("missing oauth / oidc configuration")
	}
	if err := ctx.AppIDManager.ROP("username@ibm.com", "password"); err != nil {
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
			policy := buildJWTPolicy("jwt-name-0", "default", "https://test", []v1.TargetElement{
				{
					ServiceName: "service-test",
					Paths:       []string{"/service-test"},
				},
			},
			)
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
			policy := buildJWTPolicy("jwt-name-1", "default", ctx.AppIDManager.PublicKeysURL(), []v1.TargetElement{
				{
					ServiceName: "service-test",
					Paths:       []string{"/api", "/web"},
				},
			},
			)

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			require.NoError(t, err)
		})
}

func TestInvalidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := buildJWTPolicy("jwt-name-2", "sample-app", ctx.AppIDManager.PublicKeysURL(), []v1.TargetElement{
				{
					ServiceName: "svc-sample-app",
					Paths:       []string{"/api/headers"},
				},
			},
			)

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			require.NoError(t, err)

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
					authorization: "Bearer " + *ctx.AppIDManager.Tokens.AccessToken + "123",
				},
			}

			for _, test := range tests {
				time.Sleep(1 * time.Second) // Give a second to sync adapter
				t.Run("Request", func(st *testing.T) {
					st.Parallel()
					res, err := sendAuthRequest(ctx, "GET", "/api/headers", test.authorization)
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
			policy := buildJWTPolicy("jwt-name-5", "sample-app", ctx.AppIDManager.PublicKeysURL(), []v1.TargetElement{
				{
					ServiceName: "svc-sample-app",
					Paths:       []string{"/api/headers/header1"},
				},
			},
			)

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
			policy := buildJWTPolicy("jwt-name-3", "sample-app", ctx.AppIDManager.PublicKeysURL(), []v1.TargetElement{
				{
					ServiceName: "svc-sample-app",
					Paths:       []string{"/api/headers"},
				},
			},
			)
			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			require.NoError(t, err)

			tests := []struct {
				authorization string
			}{
				{
					authorization: "Bearer " + *ctx.AppIDManager.Tokens.AccessToken,
				},
				{
					authorization: "Bearer " + *ctx.AppIDManager.Tokens.AccessToken + " " + *ctx.AppIDManager.Tokens.IdentityToken,
				},
			}

			for _, test := range tests {
				time.Sleep(1 * time.Second) // Give a second to sync adapter
				t.Run("Request", func(st *testing.T) {
					st.Parallel()
					res, err := sendAuthRequest(ctx, "GET", "/api/headers", test.authorization)
					if err != nil {
						st.Fail()
						return
					}
					require.Equal(st, http.StatusOK, res.StatusCode)
				})
			}
		})
}

func sendAuthRequest(ctx *framework.Context, method string, path string, authorization string) (*http.Response, error) {
	return ctx.SendRequest(method, path, map[string]string{"authorization": authorization})
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

func buildJWTPolicy(name string, namespace string, jwksURL string, target []v1.TargetElement) v1.JwtPolicy {
	return v1.JwtPolicy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.JwtPolicySpec{
			JwksURL: jwksURL,
			Target:  target,
		},
	}
}

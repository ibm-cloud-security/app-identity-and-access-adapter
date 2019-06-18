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
	jwtTemplatePath = "../templates/jwt_config.yaml"
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
	if err := ctx.AppIDManager.ROP("testuser", "password"); err != nil {
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

func TestInvalidJwkConfig(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			config := buildJwtConfig("jwt-name-0", "default", "https://test")
			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &config)
			if err == nil || !strings.Contains(err.Error(), "jwksUrl in body should match") {
				println(err)
				t.Fail()
			}
		})
}

func TestValidJWTCRD(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			configName := "jwt-config-1"
			config := buildJwtConfig(configName, "default", ctx.AppIDManager.PublicKeysURL())
			policy := buildJwtPolicy("jwt-name-2", "default", configName, "/api", "", "ALL")

			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &config)
			require.NoError(t, err)

			err2 := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			require.NoError(t, err2)
		})
}

func TestInvalidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := buildJwtConfig("jwt-name-2", "sample-app", ctx.AppIDManager.PublicKeysURL())

			/*, []v1.TargetElement{
				{
					ServiceName: "svc-sample-app",
					Paths:       []string{"/api/headers"},
				},
			},
			)*/

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
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken + "123",
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

func TestDeletePolicy(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := buildJwtConfig("jwt-name-5", "sample-app", ctx.AppIDManager.PublicKeysURL())

			/*,[]v1.TargetElement{
			{
				ServiceName: "svc-sample-app",
				Paths:       []string{"/api/headers"},
			},
			},
			)
			*/
			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			require.NoError(t, err)

			time.Sleep(1 * time.Second)

			res, err := sendAuthRequest(ctx, "GET", "/api/headers", "")
			require.NoError(t, err)
			require.Equal(t, http.StatusUnauthorized, res.StatusCode)

			err = ctx.CRDManager.DeleteCRD(&policy)
			require.NoError(t, err)

			time.Sleep(1 * time.Second)

			res, err = sendAuthRequest(ctx, "GET", "/api/headers", "")
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
}

func TestValidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			policy := buildJwtConfig("jwt-name-3", "sample-app", ctx.AppIDManager.PublicKeysURL())

			/*, []v1.TargetElement{
			{
				ServiceName: "svc-sample-app",
				Paths:       []string{"/api/headers"},
			},
			},
			)*/
			err := ctx.CRDManager.AddCRD(jwtTemplatePath, &policy)
			require.NoError(t, err)

			tests := []struct {
				authorization string
			}{
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
				},
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken + " " + ctx.AppIDManager.Tokens.IdentityToken,
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

func buildJwtConfig(name string, namespace string, jwksURL string) v1.JwtConfig {
	return v1.JwtConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.JwtConfigSpec{
			JwksURL: jwksURL,
		},
	}
}

func buildJwtPolicy(name string, namespace string, jwtConfigName string, exact string, prefix string, method string) v1.Policy {
	return v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PolicySpec{
			Target: []v1.TargetElement{
				{
					ServiceName: "",
					Paths: []v1.PathConfig{
						{
							Exact:  exact,
							Prefix: prefix,
							Method: method,
							Policies: []v1.PathPolicy{
								{
									PolicyType: "JWT",
									Config:     jwtConfigName,
								},
							},
						},
					},
				},
			},
		},
	}
}

package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/framework"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/framework/utils"
)

const (
	sampleAppNamespace = "sample-app"
	sampleAppService   = "svc-sample-app"
)

//
// Create a before method to setup a suite before tests execute
//
func before(ctx *framework.Context) error {
	if !utils.Exists("kubectl") {
		return errors.New("missing required executable kubectl")
	}
	if !ctx.AppIDManager.OK() {
		return errors.New("missing oauth / oidc configuration")
	}
	if err := ctx.AppIDManager.ROP(framework.DefaultUsername, framework.DefaultPassword); err != nil {
		return err
	}
	return nil
}

//
// Create a cleanup method to execute once a suite has completed
//
func after(ctx *framework.Context) error {
	_ = ctx.CRDManager.CleanUp()
	return nil
}

//
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
			config := buildJwtConfig("jwt-name-1", "default", "https://test")
			err := ctx.CRDManager.AddCRD(framework.JwtConfigTemplate, &config)
			if err == nil || !strings.Contains(err.Error(), "jwksUrl in body should match") {
				println(err)
				t.Fail()
			}
		})
}

func TestValidJWTPolicy(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			configName := "jwt-config-1"
			config := buildJwtConfig(configName, "default", ctx.AppIDManager.PublicKeysURL())
			policy := buildJwtPolicy("jwt-name-2", "default", "svc-sample-app", configName, "/api", "", "ALL")

			err := ctx.CRDManager.AddCRD(framework.JwtConfigTemplate, &config)
			require.NoError(t, err)

			err2 := ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
			require.NoError(t, err2)
		})
}

func TestInvalidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			configName := "jwt-config-0"
			randomPath := "/api/headers/" + framework.RandString(3) // Use random path to avoid caching bugs
			config := buildJwtConfig(configName, sampleAppNamespace, ctx.AppIDManager.PublicKeysURL())
			policy := buildJwtPolicy("jwt-name-3", sampleAppNamespace, sampleAppService, configName, randomPath, "", "GET")

			err := ctx.CRDManager.AddCRD(framework.JwtConfigTemplate, &config)
			require.NoError(t, err)

			err = ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
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

			time.Sleep(1 * time.Second) // Give a second to sync adapter

			for _, test := range tests {
				t.Run("Request", func(st *testing.T) {
					res, err := sendAuthRequest(ctx, "GET", randomPath, test.authorization)
					if err != nil {
						st.FailNow()
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
			configName := "jwt-config-3"
			randomPath := "/api/headers/" + framework.RandString(3) // Use random path to avoid caching bugs
			config := buildJwtConfig(configName, sampleAppNamespace, ctx.AppIDManager.PublicKeysURL())
			policy := buildJwtPolicy("jwt-name-4", sampleAppNamespace, sampleAppService, configName, randomPath, "", "ALL")

			err := ctx.CRDManager.AddCRD(framework.JwtConfigTemplate, &config)
			require.NoError(t, err)

			err = ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
			require.NoError(t, err)

			time.Sleep(1 * time.Second)

			res, err := sendAuthRequest(ctx, "GET", randomPath, "")
			require.NoError(t, err)
			require.Equal(t, http.StatusUnauthorized, res.StatusCode)

			err = ctx.CRDManager.DeleteCRD(&policy)
			require.NoError(t, err)

			time.Sleep(1 * time.Second)

			res, err = sendAuthRequest(ctx, "GET", randomPath, "")
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
}

func TestPrefixHeaderAllMethods(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			configName := "jwt-config-5"
			config := buildJwtConfig(configName, "sample-app", ctx.AppIDManager.PublicKeysURL())
			policy := buildJwtPolicy("jwt-name-5", "sample-app", "svc-sample-app", configName, "", "/api/headers", "ALL")

			err := ctx.CRDManager.AddCRD(framework.JwtConfigTemplate, &config)
			require.NoError(t, err)

			err = ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
			require.NoError(t, err)

			tests := []struct {
				authorization string
				method        string
				path          string
			}{
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
					method:        "GET",
					path:          "/api/headers/" + framework.RandString(3),
				},
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken + " " + ctx.AppIDManager.Tokens.IdentityToken,
					method:        "PUT",
					path:          "/api/headers/" + framework.RandString(3),
				},
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
					method:        "PATCH",
					path:          "/api/headers/" + framework.RandString(3),
				},
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
					method:        "POST",
					path:          "/api/headers/" + framework.RandString(3),
				},
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
					method:        "DELETE",
					path:          "/api/headers/" + framework.RandString(3),
				},
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
					method:        "PATCH",
					path:          "/api/headers/" + framework.RandString(3),
				},
			}

			_, err = sendAuthRequest(ctx, "GET", "/api/headers", tests[0].authorization)
			if err != nil {
				t.FailNow()
			}

			time.Sleep(1 * time.Second) // Give a second to sync adapter

			for _, ts := range tests {
				test := ts
				t.Run("Request", func(st *testing.T) {
					res, err := sendAuthRequest(ctx, test.method, test.path, test.authorization)
					if err != nil {
						st.FailNow()
					}
					require.Equal(st, http.StatusOK, res.StatusCode)
				})
			}
		})
}

func TestValidHeader(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			configName := "jwt-config-55"
			randomPath := "/api/headers/" + framework.RandString(3) // Use random path to avoid caching bugs
			config := buildJwtConfig(configName, sampleAppNamespace, ctx.AppIDManager.PublicKeysURL())
			policy := buildJwtPolicy("jwt-policy-6", sampleAppNamespace, sampleAppService, configName, randomPath, "", "POST")

			err := ctx.CRDManager.AddCRD(framework.JwtConfigTemplate, &config)
			require.NoError(t, err)

			err = ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
			require.NoError(t, err)

			tests := []struct {
				authorization string
				method        string
				path          string
				status        int
			}{
				{
					authorization: "Bearer " + ctx.AppIDManager.Tokens.AccessToken,
					method:        "POST",
					path:          randomPath,
					status:        http.StatusOK,
				},
				{
					authorization: "",
					method:        "GET",
					path:          randomPath,
					status:        http.StatusOK,
				},
				{
					authorization: "",
					method:        "PUT",
					path:          randomPath,
					status:        http.StatusOK,
				},
				{
					authorization: "",
					method:        "PATCH",
					path:          randomPath,
					status:        http.StatusOK,
				},
				{
					authorization: "",
					method:        "DELETE",
					path:          randomPath,
					status:        http.StatusOK,
				},
			}

			time.Sleep(2 * time.Second) // Give a second to sync adapter

			// Base case
			res, err := sendAuthRequest(ctx, "POST", randomPath, "no auth")
			if err != nil {
				t.FailNow()
			}
			require.Equal(t, http.StatusUnauthorized, res.StatusCode, "Expected path to be protected")

			for _, ts := range tests {
				test := ts
				t.Run("Request", func(st *testing.T) {
					res, err := sendAuthRequest(ctx, test.method, test.path, test.authorization)
					if err != nil {
						st.FailNow()
					}
					require.Equal(st, test.status, res.StatusCode, test.path)
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

func buildJwtPolicy(name string, namespace string, svc string, jwtConfigName string, exact string, prefix string, method string) v1.Policy {
	return v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PolicySpec{
			Target: []v1.TargetElement{
				{
					ServiceName: svc,
					Paths: []v1.PathConfig{
						{
							Exact:  exact,
							Prefix: prefix,
							Method: method,
							Policies: []v1.PathPolicy{
								{
									PolicyType: "jwt",
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

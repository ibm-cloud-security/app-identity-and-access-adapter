package oidc

import (
	"errors"
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
	sleepTime          = 5
	randomStringLength = 5
)

// ApplicationResponseHeaders models the sample application response json
type ApplicationResponseHeaders struct {
	Authorization string
	Cookie        string
}

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
		NewSuite("oidc_e2e_tests", t).
		Setup(before).
		Cleanup(after).
		Run()
}

func TestAuthorizationRedirect(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			configName := "oidc-config-1"
			config := buildOIDCConfig(ctx, configName, sampleAppNamespace)
			randomPath := "/web/home/" + framework.RandString(randomStringLength)
			policy := buildOIDCPolicy("oidc-policy-1", sampleAppNamespace, sampleAppService, configName, randomPath, "", "ALL")
			err1 := ctx.CRDManager.AddCRD(framework.OidcConfigTemplate, &config)
			err2 := ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
			require.NoError(t, err1)
			require.NoError(t, err2)

			time.Sleep(sleepTime * time.Second)

			ctx.StopHttpRedirects()
			res, err := ctx.SendRequest("GET", randomPath, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusFound, res.StatusCode)
			if !strings.HasPrefix(res.Header.Get("location"), ctx.AppIDManager.OAuthServerURL) {
				t.FailNow()
			}
		})
}

func TestE2E(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			ctx.EnableRedirects()
			configName := "oidc-config-2"
			config := buildOIDCConfig(ctx, configName, sampleAppNamespace)
			randomPath := "/web/home/" + framework.RandString(randomStringLength)
			policy := buildOIDCPolicy("oidc-policy-2", sampleAppNamespace, sampleAppService, configName, randomPath, "", "ALL")
			err1 := ctx.CRDManager.AddCRD(framework.OidcConfigTemplate, &config)
			err2 := ctx.CRDManager.AddCRD(framework.PolicyTemplate, &policy)
			require.NoError(t, err1)
			require.NoError(t, err2)

			time.Sleep(sleepTime * time.Second)

			var output ApplicationResponseHeaders
			err := ctx.AppIDManager.LoginToCloudDirectory(t, ctx.Env.ClusterRoot, randomPath, &output)
			require.NoError(t, err)

			require.NotNil(t, output)
			split := strings.Split(output.Authorization, " ")
			require.Equal(t, 3, len(split))
			require.Equal(t, split[0], "Bearer")
		})
}

func buildOIDCConfig(ctx *framework.Context, name string, namespace string) v1.OidcConfig {
	return v1.OidcConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.OidcConfigSpec{
			ClientName:   ctx.AppIDManager.ClientID,
			ClientID:     ctx.AppIDManager.ClientID,
			DiscoveryURL: ctx.AppIDManager.DiscoveryURL(),
			ClientSecret: ctx.AppIDManager.ClientSecret,
		},
	}
}

func buildOIDCPolicy(name string, namespace string, svc string, oidcConfigName string, exact string, prefix string, method string) v1.Policy {
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
									PolicyType: "oidc",
									Config:     oidcConfigName,
									Rules: []v1.Rule{
										{
											Claim: "scope",
											Match: "ALL",
											Source: "access_token",
											Values: []string{
												"openid",
											},
										},
										{
											Claim: "amr",
											Match: "ANY",
											Source: "id_token",
											Values: []string{
												"cloud_directory",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

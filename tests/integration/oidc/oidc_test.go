package oidc

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"strings"
	"testing"
)

const (
	oidcConfigTemplatePath = "./templates/oidc_config.yaml"
	oidcPolicyTemplatePath = "./templates/oidc_policy.yaml"
	sampleAppNamespace     = "sample-app"
	sampleAppService       = "svc-sample-app"
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
			config := buildOIDCConfig(ctx, "oidc-config-1", sampleAppNamespace)
			policy := buildOIDCPolicy(ctx.AppIDManager.ClientID, "oidc-policy-1", sampleAppNamespace, []v1.TargetElement{
				{
					ServiceName: sampleAppService,
					Paths:       []string{"/web/home/1"},
				},
			},
			)
			err1 := ctx.CRDManager.AddCRD(oidcConfigTemplatePath, &config)
			err2 := ctx.CRDManager.AddCRD(oidcPolicyTemplatePath, &policy)
			require.NoError(t, err1)
			require.NoError(t, err2)

			ctx.StopHttpRedirects()
			res, err := ctx.SendRequest("GET", "/web/home/1", nil)
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
			config := buildOIDCConfig(ctx, "oidc-config-2", sampleAppNamespace)
			policy := buildOIDCPolicy(ctx.AppIDManager.ClientID, "oidc-policy-2", sampleAppNamespace, []v1.TargetElement{
				{
					ServiceName: sampleAppService,
					Paths:       []string{"/web/home/2"},
				},
			},
			)
			// Apply policies
			err1 := ctx.CRDManager.AddCRD(oidcConfigTemplatePath, &config)
			err2 := ctx.CRDManager.AddCRD(oidcPolicyTemplatePath, &policy)
			require.NoError(t, err1)
			require.NoError(t, err2)

			var output ApplicationResponseHeaders
			err := ctx.AppIDManager.LoginToCloudDirectory(t, ctx.Env.ClusterRoot, "/web/home/2", &output)
			require.NoError(t, err)

			require.NotNil(t, output)
			split := strings.Split(output.Authorization, " ")
			require.Equal(t, 3, len(split))
			require.Equal(t, split[0], "Bearer")
		})
}

func buildOIDCConfig(ctx *framework.Context, name string, namespace string) v1.OidcClient {
	return v1.OidcClient{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.OidcClientSpec{
			ClientName:   ctx.AppIDManager.ClientID,
			ClientID:     ctx.AppIDManager.ClientID,
			DiscoveryURL: ctx.AppIDManager.DiscoveryURL(),
			ClientSecret: ctx.AppIDManager.ClientSecret,
		},
	}
}

func buildOIDCPolicy(clientName string, name string, namespace string, target []v1.TargetElement) v1.OidcPolicy {
	return v1.OidcPolicy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.OidcPolicySpec{
			ClientName: clientName,
			Target:     target,
		},
	}
}

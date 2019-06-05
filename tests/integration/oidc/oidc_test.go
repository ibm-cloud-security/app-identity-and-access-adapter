package oidc

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"strings"
	"testing"
)

const (
	oidcConfigTemplatePath = "./templates/oidc_config.yaml"
	oidcPolicyTemplatePath = "./templates/oidc_policy.yaml"
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
	ctx.StopHttpRedirects()
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
			config := buildOIDCConfig(ctx, "oidc-config-1", "sample-app")
			policy := buildOIDCPolicy(ctx.OAuthManager.ClientID, "oidc-policy-1", "sample-app", []v1.TargetElement{
				{
					ServiceName: "svc-sample-app",
					Paths:       []string{"/web/home/1"},
				},
			},
			)
			err := ctx.CRDManager.AddCRD(oidcConfigTemplatePath, &config)
			require.NoError(t, err)
			err = ctx.CRDManager.AddCRD(oidcPolicyTemplatePath, &policy)
			require.NoError(t, err)

			res, err := ctx.SendRequest("GET", "/web/home/1", nil)
			body, _ := ioutil.ReadAll(res.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusFound, res.StatusCode, string(body))
			if !strings.HasPrefix(res.Header.Get("location"), ctx.OAuthManager.OAuthServerURL) {
				t.FailNow()
			}
		})
}

func buildOIDCConfig(ctx *framework.Context, name string, namespace string) v1.OidcClient {
	return v1.OidcClient{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.OidcClientSpec{
			ClientName:   ctx.OAuthManager.ClientID,
			ClientID:     ctx.OAuthManager.ClientID,
			DiscoveryURL: ctx.OAuthManager.DiscoveryURL(),
			ClientSecret: ctx.OAuthManager.ClientSecret,
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

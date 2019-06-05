package oidc

import (
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"testing"
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
		})
}

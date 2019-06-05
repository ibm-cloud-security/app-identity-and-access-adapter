package sample

import (
	"fmt"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"testing"
)

///
// Create a before method to setup a suite before tests execute
//
func before(ctx *framework.Context) error {
	_, _ = utils.Shell("ls")
	fmt.Printf("Before test method : %v\n", ctx)
	return nil
}

///
// Create a cleanup method to execute once a suite has completed
//
func after(ctx *framework.Context) error {
	fmt.Printf("After test method : %v\n", ctx)
	return nil
}

///
// Test main runs before ALL suite methods run
// and begins test execution
//
func TestMain(t *testing.M) {
	framework.
		NewSuite("sample_test", t).
		Setup(before).
		Cleanup(after).
		Run()
}

///
// Example: test calls the sample application's endpoint
//
func TestOK(t *testing.T) {
	framework.
		NewTest(t).
		Run(func(ctx *framework.Context) {
			_, _ = ctx.SendAuthRequest("GET", "/", "")
		})

}

package e2e

import (
	"context"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework"
	"testing"
)

func setupENV(ctx context.Context) error {
	println("Setup is running")
	return nil
}

func TestMain(t *testing.M) {
	framework.
		NewSuite("sample", t).
		Setup(setupENV).
		Run()
}

func TestOK(t *testing.T) {
	result, err := framework.Shell("source ../bin/configure_cluster.sh")
	println(result, err.Error())
	result, err = framework.Shell("kubectl get namespaces")
	println(result, err)
}

func TestFail(t *testing.T) {
	println("Failing test")
	//t.Fail()
}

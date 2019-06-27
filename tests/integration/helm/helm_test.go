package helm

import (
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/framework"
	"testing"
)

func setupENV(ctx *framework.Context) error {
	println("Special setup is running")
	return nil
}

func cleanupENV(ctx *framework.Context) error {
	return nil
}

func TestMain(t *testing.M) {
	framework.
		NewSuite("Helm tests", t).
		Setup(setupENV).
		Cleanup(cleanupENV).
		Run()
}

func TestHelmInstall(t *testing.T) {
	/*
		err := utils.HelmInstall("../../../helm/ibmcloudappid", "ibmcloudappid", "../../../helm/ibmcloudappid/values.yaml", "istio-system", "")
		if err != nil {
			println(err.Error())
			t.Fail()
		}
	*/
}

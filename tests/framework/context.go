package framework

import (
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"os"
)

type Env struct {
	ClusterRoot string
	KubeConfig  string
}

type Context struct {
	// Test ID
	testID string

	CRDManager *CRDManager

	OAuthManager *OAuthManager

	Env *Env
}

func NewContext(testID string) *Context {
	ctx := &Context{
		testID: testID,
		Env: &Env{
			os.Getenv("CLUSTER_ROOT"),
			os.Getenv("KUBECONFIG"),
		},
		OAuthManager: &OAuthManager{
			os.Getenv("APPID_CLIENT_ID"),
			os.Getenv("APPID_CLIENT_SECRET"),
			os.Getenv("APPID_OAUTH_SERVER_URL"),
			nil,
			networking.New(),
		},
	}
	mgr := &CRDManager{context: ctx}
	ctx.CRDManager = mgr
	return ctx
}

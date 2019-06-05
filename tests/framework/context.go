package framework

import (
	"fmt"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/networking"
	"net/http"
	"os"
)

// Env models the kubernetes environment
type Env struct {
	ClusterRoot string
	KubeConfig  string
}

// Context models the test environment
type Context struct {
	testID       string
	CRDManager   *CRDManager
	OAuthManager *OAuthManager
	Env          *Env
	client       *http.Client
}

// NewContext creates a new test suite context
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
		client: &http.Client{},
	}
	mgr := &CRDManager{context: ctx}
	ctx.CRDManager = mgr
	return ctx
}

// SendRequest issues a new http request with an authorization header
func (c *Context) SendRequest(method string, path string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.Env.ClusterRoot+path, nil)
	if err != nil {
		fmt.Printf("Could not send request %s\n", err.Error())
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.client.Do(req)
}

func (c *Context) StopHttpRedirects() {
	c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

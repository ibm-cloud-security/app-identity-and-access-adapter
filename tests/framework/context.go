package framework

import (
	"fmt"
	"net/http"
	"os"
)

const (
	clusterRoot = "CLUSTER_ROOT"
	kubeConfig  = "KUBECONFIG"
)

const (
	templatesDir       = "../templates"
	JwtConfigTemplate  = templatesDir + "/jwtconfig.yaml"
	OidcConfigTemplate = templatesDir + "/oidcconfig.yaml"
	PolicyTemplate     = templatesDir + "/policy.yaml"
)

// Env models the kubernetes environment
type Env struct {
	ClusterRoot string
	KubeConfig  string
}

// NewEnv returns a new ENV instance
func NewEnv() *Env {
	fmt.Printf("Printing env variables \n",)
	for _, e := range os.Environ() {
		fmt.Println(e)
	}
	return &Env{
		os.Getenv(clusterRoot),
		os.Getenv(kubeConfig),
	}
}

// Context models the test environment
type Context struct {
	testID        string
	CRDManager    *CRDManager
	AppIDManager  *AppIDManager
	Env           *Env
	SessionCookie *http.Cookie
	client        *http.Client
}

// NewContext creates a new test suite context
func NewContext(testID string) *Context {
	ctx := &Context{
		testID:       testID,
		Env:          NewEnv(),
		AppIDManager: NewAppIDManager(),
		client:       &http.Client{},
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

// StopHttpRedirects configures the default client to ignore HTTP redirects
func (c *Context) StopHttpRedirects() {
	c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

// EnableRedirects configures the default client to follow HTTP redirects
func (c *Context) EnableRedirects() {
	c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return nil
	}
}

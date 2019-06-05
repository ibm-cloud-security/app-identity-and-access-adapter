package framework

import (
	"encoding/json"
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
	}
	mgr := &CRDManager{context: ctx}
	ctx.CRDManager = mgr
	return ctx
}

// SendAuthRequest issues a new http request with an authorization header
func (c *Context) SendAuthRequest(method string, path string, authorization string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.Env.ClusterRoot+path, nil)
	if err != nil {
		fmt.Printf("Could not send request %s\n", err.Error())
		return nil, err
	}
	req.Header.Set("authorization", authorization)
	client := &http.Client{}
	return client.Do(req)
}

// SendRequest issues a new http request
func (c *Context) SendRequest(path string, status int, ret interface{}) (err error) {
	req, err := http.NewRequest("GET", c.Env.ClusterRoot+path, nil)
	if err != nil {
		fmt.Printf("Could not send request\n")
		return err
	}

	client := &http.Client{}
	// Issue original request
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed\n")
		return err
	}

	// Check status code
	if res.StatusCode != status {
		fmt.Printf("Unexpected response for request.\n")
		return fmt.Errorf("unexpected response for request to %s | status code: %d\n", req.URL.Path, res.StatusCode)
	}

	if ret != nil {
		if err := json.NewDecoder(res.Body).Decode(ret); err != nil {
			fmt.Printf("Could not parse request body.\n")
			return err
		}
	}

	return nil
}

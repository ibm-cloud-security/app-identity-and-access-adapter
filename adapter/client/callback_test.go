package client

import (
	"net/url"
	"testing"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/fake"
)

func TestCallbackURLForTarget(t *testing.T) {
	tests := []struct {
		CallbackDef        string
		Scheme, Host, Path string
		Result             string
	}{
		{ // http scheme test
			"",
			"http", "test.com", "/admin",
			"http://test.com/admin/oidc/callback",
		},
		{ // default relative callback
			"",
			"https", "test.com", "/admin",
			"https://test.com/admin/oidc/callback",
		},
		{ // relative URI
			"custom/relative/path",
			"https", "test.com", "/admin",
			"https://test.com/admin/custom/relative/path",
		},
		{ // relative URI already appended
			"custom/relative/path",
			"https", "test.com", "/admin/custom/relative/path",
			"https://test.com/admin/custom/relative/path",
		},
		{ // absolute URI
			"/absolute/uri/callback",
			"https", "test.com", "/admin",
			"https://test.com/absolute/uri/callback",
		},
		{ // full URL (http)
			"http://test.com/my/callback",
			"http", "test.com", "/admin",
			"http://test.com/my/callback",
		},
		{ // full URL (https)
			"https://test.com/my/callback",
			"https", "test.com", "/admin",
			"https://test.com/my/callback",
		},
	}

	for n, tst := range tests {
		cli := fake.NewClientWithCallback(nil, tst.CallbackDef)

		res := CallbackURLForTarget(cli, tst.Scheme, tst.Host, tst.Path)
		if res != tst.Result {
			t.Fatalf("TestCallbackURLForTarget#%d CallbackURLForTarget failed.\n"+
				" Expected: %s\n Got: %s", n, tst.Result, res)
		}

		resURL, err := url.Parse(res)
		if err != nil {
			t.Fatalf("TestCallbackURLForTarget#%d failed to parse URL returned from CallbackURLForTarget %s: %s",
				n, res, err.Error())
		}

		if !IsCallbackRequest(cli, resURL.Scheme, resURL.Host, resURL.Path) {
			t.Fatalf("TestCallbackURLForTarget#%d IsCallbackRequest check not returning true\n"+
				" scheme: %s, host: %s, path: %s", n, resURL.Scheme, resURL.Host, resURL.Path)
		}
	}
}

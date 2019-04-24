// +build testtools
package testing

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
)

// HTTPClient mock
func HTTPClient(handler http.Handler) (*http.Client, *httptest.Server) {
	s := httptest.NewServer(handler)

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, s.Listener.Addr().String())
			},
		},
	}

	return cli, s
}

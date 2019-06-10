package networking

/*
import (
	"net/http"
)

const (
	filterType   = "xFilterType"
	istioAdapter = "IstioAdapter"
)

// AdapterRoundTripper provides a wrapper for *http.Client to abstract shared responsibilities
type AdapterRoundTripper struct{}

func NewAdapterRoundTripper() http.RoundTripper {
	return &AdapterRoundTripper{}
}

// RoundTrip implements the RoundTripper interface - appends shared headers and then calls the default round tripper
func (*AdapterRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(filterType, istioAdapter)
	return http.DefaultTransport.RoundTrip(req)
}
*/

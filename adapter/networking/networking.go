package networking

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"istio.io/pkg/log"
)

const (
	filterType     = "xFilterType"
	istioAdapter   = "IstioAdapter"
	defaultTimeout = 5 * time.Second
)

// OK represents types capable of validating themselves.
type OK interface {
	OK() error
}

// HttpClient provides a wrapper for *http.Client to abstract shared responsibilities
type HttpClient struct {
	Client *http.Client
}

// New creates a new HTTPClient
func New() *HttpClient {
	return &HttpClient{
		&http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Do performs an Http request, decodes and validates the response
func (c *HttpClient) Do(req *http.Request, status int, v OK) error {
	// Append shared headers
	req.Header.Set(filterType, istioAdapter)

	// Issue original request
	res, err := c.Client.Do(req)
	if err != nil {
		log.Errorf("Request failed: %s", err)
		return err
	}

	// Check status code
	if res.StatusCode != status {
		log.Debugf("Unexpected response for request to %s | status code: %d", req.URL.Path, res.StatusCode)
		return fmt.Errorf("unexpected response for request to %s | status code: %d", req.URL.Path, res.StatusCode)
	}

	// Decode response
	if err := decodeJSON(res, v); err != nil {
		log.Infof("Unexpected response for request to %s | status code: %d", req.URL.Path, res.StatusCode)
		return err
	}

	return nil
}

// decodeJSON parses a JSON body and calls validate
func decodeJSON(r *http.Response, v OK) error {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		log.Debugf("Could not parse request body - status code: %d", r.StatusCode)
		return err
	}
	return v.OK()
}

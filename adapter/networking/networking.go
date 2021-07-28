package networking

import (
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"
)

const (
	filterType     = "x-filter-type"
	istioAdapter   = "IstioAdapter"
	defaultTimeout = 5 * time.Second
)

// OK represents types capable of validating themselves.
type OK interface {
	OK() error
}

// HTTPClient provides a wrapper for *http.Client to abstract shared responsibilities
type HTTPClient struct {
	Client *http.Client
}

// New creates a new HTTPClient
func New() *HTTPClient {
	return &HTTPClient{
		&http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Do performs an Http request, decodes and validates the response
func (c *HTTPClient) Do(req *http.Request, successV, failureV OK) (*http.Response, error) {
	// Append shared headers
	req.Header.Set(filterType, istioAdapter)

	// Issue original request
	res, err := c.Client.Do(req)
	if err != nil {
		zap.L().Info("Request failed", zap.String("url", req.URL.Path), zap.Error(err))
		return res, err
	}

	defer res.Body.Close()

	// Decode from json
	if successV != nil || failureV != nil {
		err = decodeResponse(res, successV, failureV)
	}

	return res, err
}

// decodeResponse parses a response into the expected success or failure object
func decodeResponse(res *http.Response, successV, failureV OK) error {
	if code := res.StatusCode; 200 <= code && code <= 299 {
		if successV != nil {
			return decodeJSON(res, successV)
		}
	} else {
		if failureV != nil {
			return decodeJSON(res, failureV)
		}
	}
	return nil
}

// decodeJSON parses a JSON body and calls validate
func decodeJSON(r *http.Response, v OK) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		zap.L().Debug("Could not parse response body", zap.Error(err))
		return err
	}
	return v.OK()
}

// Retry provides a recursive function retry implementation
func Retry(attempts int, sleep time.Duration, fn func() (interface{}, error)) (interface{}, error) {
	res, err := fn()
	if err != nil {
		attempts--
		if attempts > 0 {
			zap.L().Debug("Call failed, retrying.", zap.Int("attempts", attempts))
			time.Sleep(sleep)
			return Retry(attempts, 2*sleep, fn)
		}
		return nil, err
	}
	return res, nil
}

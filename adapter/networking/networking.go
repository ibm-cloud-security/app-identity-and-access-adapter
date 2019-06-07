package networking

import (
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"time"
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
func (c *HTTPClient) Do(req *http.Request, status int, v OK) error {
	// Append shared headers
	req.Header.Set(filterType, istioAdapter)

	// Issue original request
	res, err := c.Client.Do(req)
	if err != nil {
		zap.L().Info("Request failed", zap.String("url", req.URL.Path), zap.Error(err))
		return err
	}

	defer res.Body.Close()

	// Check status code
	if res.StatusCode != status {
		body, _ := ioutil.ReadAll(res.Body)
		zap.L().Info("Unexpected response for request.",
			zap.String("url", req.URL.Path),
			zap.Int("status", res.StatusCode),
			zap.String("response_body", string(body)))
		return fmt.Errorf("unexpected response for request to %s | status code: %d | body %s", req.URL.String(), res.StatusCode, string(body))
	}

	// Decode response
	if err := decodeJSON(res, v); err != nil {
		zap.L().Info("Unexpected response for request.", zap.String("url", req.URL.Path), zap.Int("status", res.StatusCode))
		return err
	}

	return nil
}

// decodeJSON parses a JSON body and calls validate
func decodeJSON(r *http.Response, v OK) error {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		zap.L().Debug("Could not parse request body.", zap.Error(err))
		return err
	}
	return v.OK()
}

// retry provides a recursive function retry implementation
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

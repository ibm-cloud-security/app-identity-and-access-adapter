package framework

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (e *Env) SendBasicRequest(method string, path string, authHeader string) (*http.Response, error) {
	req, err := http.NewRequest(method, e.ClusterRoot+path, nil)
	if err != nil {
		fmt.Printf("Could not send request %s\n", err.Error())
		return nil, err
	}
	req.Header.Set("authorization", authHeader)
	client := &http.Client{}
	return client.Do(req)
}

func (e *Env) SendRequest(path string, status int, ret interface{}) (err error) {
	req, err := http.NewRequest("GET", e.ClusterRoot+path, nil)
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

package ibmcloudappid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"istio.io/istio/pkg/log"
)

const (
	duration = time.Millisecond * 1000
)

// Monitor tracks kubernetes data with App ID
type Monitor interface {
	Start()
	Stop() error
}

type defaultMonitor struct {
	cfg    *AppIDConfig
	ticker *time.Ticker
}

// NewMonitor creates an App ID Monitor object
func NewMonitor(cfg *AppIDConfig) (Monitor, error) {
	monitor := &defaultMonitor{
		cfg:    cfg,
		ticker: time.NewTicker(time.Millisecond * 1000),
	}

	go func() {
		for range monitor.ticker.C {
			registerCluster(cfg)
		}
	}()

	return monitor, nil
}

/// Starts the App ID Monitoring Service
func (m *defaultMonitor) Start() {
	if m != nil {
		m.ticker.Stop()
	}
	m.ticker = time.NewTicker(time.Millisecond * 1000)

	go func() {
		for range m.ticker.C {
			registerCluster(m.cfg)
		}
	}()
}

/// Starts the App ID Monitoring Service
func (m *defaultMonitor) Stop() error {
	if m != nil {
		m.ticker.Stop()
		return nil
	}
	return errors.New("Missing active ticker")
}

func registerCluster(config *AppIDConfig) {
	requestURL := config.AppidURL + "/clusters"
	log.Infof(">> registerCluster :: clusterGuid %s, requestUrl %s", config.ClusterGUID, requestURL)

	jsonMap := map[string]string{
		"guid":     config.ClusterGUID,
		"name":     config.ClusterName,
		"location": config.ClusterLocation,
		"type":     config.ClusterType,
	}
	jsonString, _ := json.Marshal(jsonMap)

	response, err := http.Post(requestURL, "application/json", bytes.NewBuffer(jsonString))

	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("%s", err)
		os.Exit(1)
	}

	var jsonObj map[string]interface{}
	json.Unmarshal(contents, &jsonObj)
	isProtectionEnabled := jsonObj["protectionEnabled"].(bool)
	config.IsProtectionEnabled = isProtectionEnabled
	log.Infof("Protected: %t; %s", config.IsProtectionEnabled, string(contents))
}

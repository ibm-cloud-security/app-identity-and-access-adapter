package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"istio.io/istio/mixer/adapter/ibmcloudappid"
	"istio.io/istio/pkg/log"
)

func main() {
	log.Info(">> main() :: Starting ibmcloudappid adapter")

	cfg, err := ibmcloudappid.NewConfig()
	if err != nil {
		log.Infof("Failed to create the Ingress-Auth service: %s", err)
	}

	s, err := ibmcloudappid.NewAppIDAdapter(cfg)
	if err != nil {
		log.Errorf("Unable to start server: %v", err)
		os.Exit(-1)
	}

	ticker := time.NewTicker(time.Millisecond * 1000)
	go func() {
		for range ticker.C {
			registerCluster(cfg)
		}
	}()

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

func registerCluster(config *ibmcloudappid.Config) {
	requestURL := config.AppidURL + "/clusters"
	log.Infof(">> registerCluster :: clusterGuid %s, requestUrl %s", config.ClusterGUID, requestURL)

	jsonMap := map[string]string{"guid": config.ClusterGUID, "name": config.ClusterName, "location": config.ClusterLocation}
	jsonString, _ := json.Marshal(jsonMap)

	response, err := http.Post(requestURL, "application/json", bytes.NewBuffer(jsonString))

	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	} else {
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
}

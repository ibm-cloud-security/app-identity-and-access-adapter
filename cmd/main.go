package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"istio.io/istio/mixer/adapter/ibmcloudappid"
	"istio.io/istio/pkg/log"
	"net/http"
	"os"
	"time"
)

var appidUrl, appidApiKey, clusterName, clusterGuid, clusterLocation string

func main() {
	log.Info (">> main() :: Starting ibmcloudappid adapter")

	appidUrl = os.Getenv("APPID_URL");
	appidApiKey = os.Getenv("APPID_APIKEY");
	clusterName = os.Getenv("CLUSTER_NAME");
	clusterGuid = os.Getenv("CLUSTER_GUID");
	clusterLocation = os.Getenv("CLUSTER_LOCATION");

	log.Infof("APPID_URL: %s", appidUrl);
	log.Infof("APPID_APIKEY: %s", appidApiKey);
	log.Infof("CLUSTER_NAME: %s", clusterName);
	log.Infof("CLUSTER_GUID: %s", clusterGuid);
	log.Infof("CLUSTER_LOCATION: %s", clusterLocation);

	if (appidUrl == "" || appidApiKey == "" || clusterName == "" || clusterGuid == "" || clusterLocation == ""){
		log.Errorf("Missing one of the following environment variables: APPID_URL APPID_APIKEY CLUSTER_NAME CLUSTER_GUID CLUSTER_LOCATION");
		log.Error("Shutting down....");
		return;
	}

	port := ""
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// s, err := mygrpcadapter.NewMyGrpcAdapter(addr)
	s, err := ibmcloudappid.NewAppidAdapter(port)

	if err != nil {
		log.Errorf("Unable to start server: %v", err)
		//fmt.Printf("Unable to start server: %v", err)
		os.Exit(-1)
	}

	ticker := time.NewTicker(time.Millisecond * 1000)
	go func(){
		for range ticker.C {
			registerCluster()
		}
	}()

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

func registerCluster() {
	requestUrl := appidUrl + "/clusters"
	log.Infof(">> registerCluster :: clusterGuid %s, requestUrl %s", clusterGuid, requestUrl);

	jsonMap := map[string]string {"guid":clusterGuid, "name":clusterName, "location":clusterLocation}
	jsonString, _:= json.Marshal(jsonMap)

	response, err := http.Post(requestUrl, "application/json", bytes.NewBuffer(jsonString))

	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	} else {
		defer response.Body.Close()
		contents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("%s", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(contents))
	}
}
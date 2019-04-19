package main

import (
	"os"

	"istio.io/istio/mixer/adapter/ibmcloudappid"
	"istio.io/istio/pkg/log"
)

func main() {
	log.Info("Starting ibmcloudappid adapter")

	// Create App ID Adapter
	s, err := ibmcloudappid.NewAppIDAdapter()
	if err != nil {
		log.Errorf("Failed to create ibmcloudappid.NewAppIDAdapter: %s", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

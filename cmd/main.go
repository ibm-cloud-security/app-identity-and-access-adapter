package main

import (
	"os"

	"istio.io/istio/mixer/adapter/ibmcloudappid"
	"istio.io/istio/pkg/log"
)

func main() {
	log.Info(">> main() :: Starting ibmcloudappid adapter")

	// Ensure we have correct configuration
	cfg, err := ibmcloudappid.NewConfig()
	if err != nil {
		log.Infof("Failed to create the Ingress-Auth service: %s", err)
		os.Exit(-1)
	}

	// Start communication with App ID
	monitor, err := ibmcloudappid.NewMonitor(cfg)
	if err != nil {
		log.Errorf("Could not create App ID monitor: %v", err)
		os.Exit(-1)
	}
	monitor.Start()

	// Create App ID Adapter
	s, err := ibmcloudappid.NewAppIDAdapter(cfg)
	if err != nil {
		log.Errorf("Unable to start server: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

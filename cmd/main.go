package main

import (
	"os"

	"istio.io/istio/mixer/adapter/ibmcloudappid"
	"istio.io/istio/pkg/log"
)

func main() {
	log.Info(">> main() :: Starting ibmcloudappid adapter")

	// Ensure we have correct configuration
	cfg, err := ibmcloudappid.NewAppIDConfig()
	if err != nil {
		log.Infof("Failed to create ibmcloudappid.NewAppIDConfig: %s", err)
		os.Exit(-1)
	}

	// Start communication with App ID
	monitor, err := ibmcloudappid.NewMonitor(cfg)
	if err != nil {
		log.Errorf("Failed to create ibmcloudappid.NewMonitor: %s", err)
		os.Exit(-1)
	}
	monitor.Start()

	// Create App ID Adapter
	s, err := ibmcloudappid.NewAppIDAdapter(cfg)
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

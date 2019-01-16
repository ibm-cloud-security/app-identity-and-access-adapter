package ibmcloudappid

import (
	"errors"
	"os"
	"time"

	"istio.io/istio/pkg/log"
)

const (
	appIDURL               = "APPID_URL"
	appIDApiKey            = "APPID_APIKEY"
	TenantID               = "TENANT_ID"
	clusterName            = "CLUSTER_NAME"
	clusterGUID            = "CLUSTER_GUID"
	clusterLocation        = "CLUSTER_LOCATION"
	defaultPort            = "47304"
	defaultPubkeysInterval = 60 * time.Minute
	minPubkeyInterval      = 60 * time.Minute
)

// Config encapsulates REST server configuration parameters
type Config struct { // structure should not be marshaled to JSON, not even using defaults
	AppidURL            string `json:"-"`
	AppidAPIKey         string `json:"-"`
	TenantID            string `json:"-"`
	ClusterName         string `json:"-"`
	ClusterGUID         string `json:"-"`
	ClusterLocation     string `json:"-"`
	Port                string `json:"-"`
	IsProtectionEnabled bool   `json:"-"`
}

// NewConfig creates a configuration object
func NewConfig() (*Config, error) {
	cfg := &Config{}

	cfg.TenantID = os.Getenv(TenantID)
	cfg.AppidURL = os.Getenv(appIDURL)
	cfg.AppidAPIKey = os.Getenv(appIDApiKey)
	cfg.ClusterName = os.Getenv(clusterName)
	cfg.ClusterGUID = os.Getenv(clusterGUID)
	cfg.ClusterLocation = os.Getenv(clusterLocation)

	log.Infof("TENANT_ID: %s", cfg.TenantID)
	log.Infof("APPID_URL: %s", cfg.AppidURL)
	log.Infof("APPID_APIKEY: %s", cfg.AppidAPIKey)
	log.Infof("CLUSTER_NAME: %s", cfg.ClusterName)
	log.Infof("CLUSTER_GUID: %s", cfg.ClusterGUID)
	log.Infof("CLUSTER_LOCATION: %s", cfg.ClusterLocation)

	if cfg.AppidURL == "" || cfg.AppidAPIKey == "" || cfg.ClusterName == "" || cfg.ClusterGUID == "" || cfg.ClusterLocation == "" || cfg.TenantID == "" {
		log.Errorf("Missing one of the following environment variables: APPID_URL APPID_APIKEY CLUSTER_NAME CLUSTER_GUID CLUSTER_LOCATION")
		log.Error("Shutting down....")
		return nil, errors.New("Missing one or more env variables")
	}

	cfg.Port = defaultPort
	if len(os.Args) > 1 {
		cfg.Port = os.Args[1]
	}

	return cfg, nil
}

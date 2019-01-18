package ibmcloudappid

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"istio.io/istio/pkg/log"
)

const (
	APPID_URL              = "APPID_URL"
	APPID_APIKEY           = "APPID_APIKEY"
	CLUSTER_NAME           = "CLUSTER_NAME"
	CLUSTER_GUID           = "CLUSTER_GUID"
	CLUSTER_TYPE           = "CLUSTER_TYPE"
	CLUSTER_LOCATION       = "CLUSTER_LOCATION"
	DEFAULT_PORT           = "47304"
	defaultPubkeysInterval = 60 * time.Minute
	minPubkeyInterval      = 60 * time.Minute
)

// AppIDConfig encapsulates REST server configuration parameters
type AppIDConfig struct { // private fields should not be marshaled to json
	AppidURL            string       `json:"appidURL"`
	AppidAPIKey         string       `json:"-"`
	ClusterName         string       `json:"clusterName"`
	ClusterGUID         string       `json:"clusterGUID"`
	ClusterType         string       `json:"clusterType"`
	ClusterLocation     string       `json:"clusterLocation"`
	Port                string       `json:"port"`
	IsProtectionEnabled bool         `json:"isProtectionEnabled"`
	Credentials         *Credentials `json:"credentials"`
}

// Credentials encapsulates App ID instance credentials
type Credentials struct {
	TenantID         string `json:"tenantId"`
	ClientID         string `json:"clientId"`
	Secret           string `json:"secret"`
	AuthorizationURL string `json:"authorizationUrl"`
	TokenURL         string `json:"tokenUrl"`
	UserinfoURL      string `json:"userinfoUrl"`
	JwksURL          string `json:"jwksUrl"`
}

// NewAppIDConfig creates a configuration object
func NewAppIDConfig() (*AppIDConfig, error) {
	cfg := &AppIDConfig{}

	// Retrieve Environment Variables
	cfg.AppidURL = os.Getenv(APPID_URL)
	cfg.AppidAPIKey = os.Getenv(APPID_APIKEY)
	cfg.ClusterName = os.Getenv(CLUSTER_NAME)
	cfg.ClusterGUID = os.Getenv(CLUSTER_GUID)
	cfg.ClusterType = os.Getenv(CLUSTER_TYPE)
	cfg.ClusterLocation = os.Getenv(CLUSTER_LOCATION)

	if cfg.AppidURL == "" || cfg.AppidAPIKey == "" || cfg.ClusterName == "" || cfg.ClusterGUID == "" || cfg.ClusterLocation == "" || cfg.ClusterType == "" {
		log.Errorf("Missing one of the following environment variables: APPID_URL APPID_APIKEY CLUSTER_NAME CLUSTER_GUID CLUSTER_LOCATION CLUSTER_TYPE")
		log.Error("Shutting down....")
		return nil, errors.New("Missing one or more env variables")
	}

	cfg.Port = DEFAULT_PORT
	if len(os.Args) > 1 {
		cfg.Port = os.Args[1]
	}

	// Retrieve App ID instance configuration
	credentials, err := retrieveAppIDConfig(cfg.AppidURL, cfg.AppidAPIKey)
	if err != nil {
		log.Error("Shutting down....")
		return nil, errors.New("Could not retrieve App ID instance credentials")
	}

	cfg.Credentials = credentials

	res, _ := json.MarshalIndent(cfg, "", "\t")
	log.Info(string(res))

	return cfg, nil
}

func retrieveAppIDConfig(url string, apiKey string) (*Credentials, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", url+"/config", nil)
	req.Header.Add("X-Api-Key", apiKey)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	appidCreds := Credentials{}
	err = json.Unmarshal(body, &appidCreds)
	if err != nil {
		return nil, err
	}
	return &appidCreds, nil
}

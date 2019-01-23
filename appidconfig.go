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

	log.Infof("APPID_URL: %s", cfg.AppidURL)
	log.Infof("APPID_APIKEY: %s", cfg.AppidAPIKey)
	log.Infof("CLUSTER_NAME: %s", cfg.ClusterName)
	log.Infof("CLUSTER_TYPE: %s", cfg.ClusterType)
	log.Infof("CLUSTER_LOCATION: %s", cfg.ClusterLocation)
	log.Infof("CLUSTER_GUID: %s", cfg.ClusterGUID)

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
	log.Infof("Retrieved configuration: %s", string(res))

	return cfg, nil
}

func retrieveAppIDConfig(url string, apiKey string) (*Credentials, error) {
	log.Infof(">> retrieveAppIDConfig")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", url+"/config", nil)
	req.Header.Add("X-Api-Key", apiKey)
	if err != nil {
		log.Infof("<< retrieveAppIDConfig FAIL http.NewRequest :: %s", err)
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Infof("<< retrieveAppIDConfig FAIL client.Do :: %s", err)
		return nil, err
	}

	if resp.StatusCode == 403 {
		log.Infof("<< retrieveAppIDConfig 403")
		return nil, errors.New("403 Forbidden")
	}

	body, err := ioutil.ReadAll(resp.Body)
	log.Infof("retrieveAppIDConfig Response body: %s", string(body))

	if err != nil {
		log.Infof("<< retrieveAppIDConfig FAIL ioutil.ReadAll :: %s", err)
		return nil, err
	}

	defer resp.Body.Close()


	appidCreds := Credentials{}
	err = json.Unmarshal(body, &appidCreds)
	if err != nil {
		log.Infof("<< retrieveAppIDConfig FAIL json.Unmarshal :: %s", err)
		return nil, err
	}
	log.Infof("<< retrieveAppIDConfig OK")

	return &appidCreds, nil
}

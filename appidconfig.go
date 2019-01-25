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
	appIDURL        = "APPID_URL"
	appIDApiKey     = "APPID_APIKEY"
	clusterName     = "CLUSTER_NAME"
	clusterGUID     = "CLUSTER_GUID"
	clusterType     = "CLUSTER_TYPE"
	clusterLocation = "CLUSTER_LOCATION"
	defaultPort     = "47304"
)

// AppIDConfig encapsulates REST server configuration parameters
type AppIDConfig struct { // private fields should not be marshaled to json
	AppidURL    string       `json:"appidURL"`
	AppidAPIKey string       `json:"-,"`
	ClusterInfo *ClusterInfo `json:"clusterName"`
	Port        string       `json:"port"`
	Credentials *Credentials `json:"credentials"`
}

// ClusterInfo encapsulates the Kubernetes cluster information
type ClusterInfo struct {
	Name                string             `json:"name"`
	GUID                string             `json:"guid"`
	Type                string             `json:"type"`
	Location            string             `json:"location"`
	Services            map[string]Service `json:"services,string"`
	IsProtectionEnabled bool               `json:"protectionEnabled"`
}

// Service encapsulates a Kubernetes Service
type Service struct {
	Name                string `json:"name"`
	Namespace           string `json:"namespace"`
	IsProtectionEnabled bool   `json:"IsProtectionEnabled"`
}

// Credentials encapsulates App ID instance credentials
type Credentials struct {
	TenantID         string `json:"tenantId"`
	ClientID         string `json:"clientId"`
	Secret           string `json:"-,"`
	AuthorizationURL string `json:"authorizationUrl"`
	TokenURL         string `json:"tokenUrl"`
	UserinfoURL      string `json:"userinfoUrl"`
	JwksURL          string `json:"jwksUrl"`
}

// NewAppIDConfig creates a configuration object
func NewAppIDConfig() (*AppIDConfig, error) {
	cfg := &AppIDConfig{}

	// Retrieve Environment Variables
	cfg.AppidURL = os.Getenv(appIDURL)
	cfg.AppidAPIKey = os.Getenv(appIDApiKey)
	cfg.ClusterInfo = &ClusterInfo{
		Name:     os.Getenv(clusterName),
		GUID:     os.Getenv(clusterGUID),
		Type:     os.Getenv(clusterType),
		Location: os.Getenv(clusterLocation),
		Services: make(map[string]Service),
	}

	log.Infof("APPID_URL: %s", cfg.AppidURL)
	log.Infof("APPID_APIKEY: %s", cfg.AppidAPIKey)
	log.Infof("CLUSTER_NAME: %s", cfg.ClusterInfo.Name)
	log.Infof("CLUSTER_TYPE: %s", cfg.ClusterInfo.Type)
	log.Infof("CLUSTER_LOCATION: %s", cfg.ClusterInfo.Location)
	log.Infof("CLUSTER_GUID: %s", cfg.ClusterInfo.GUID)

	if cfg.AppidURL == "" || cfg.AppidAPIKey == "" || cfg.ClusterInfo.Name == "" || cfg.ClusterInfo.GUID == "" || cfg.ClusterInfo.Location == "" || cfg.ClusterInfo.Type == "" {
		log.Errorf("Missing one of the following environment variables: APPID_URL APPID_APIKEY CLUSTER_NAME CLUSTER_GUID CLUSTER_LOCATION CLUSTER_TYPE")
		log.Error("Shutting down....")
		return nil, errors.New("Missing one or more env variables")
	}

	cfg.Port = defaultPort
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
	log.Infof("Retrieved configuration:\n %s", string(res))

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
		log.Errorf("<< retrieveAppIDConfig FAIL http.NewRequest :: %s", err)
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("<< retrieveAppIDConfig FAIL client.Do :: %s", err)
		return nil, err
	}

	if resp.StatusCode == 403 {
		log.Errorf("<< retrieveAppIDConfig 403")
		return nil, errors.New("403 Forbidden")
	}

	body, err := ioutil.ReadAll(resp.Body)
	log.Debugf("retrieveAppIDConfig Response body: %s", string(body))

	if err != nil {
		log.Errorf("<< retrieveAppIDConfig FAIL ioutil.ReadAll :: %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	appidCreds := Credentials{}
	err = json.Unmarshal(body, &appidCreds)
	if err != nil {
		log.Errorf("<< retrieveAppIDConfig FAIL json.Unmarshal :: %s", err)
		return nil, err
	}
	log.Debugf("<< retrieveAppIDConfig OK")

	return &appidCreds, nil
}

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
type AppIDConfig struct {
	// private fields should not be marshaled to json
	AppidURL          string             `json:"appidURL"`
	AppidAPIKey       string             `json:"-,"`
	ClusterInfo       *ClusterInfo       `json:"clusterInfo"`
	ClusterPolicies   *ClusterPolicies   `json:"clusterPolicies"`
	Port              string             `json:"port"`
	ClientCredentials *ClientCredentials `json:"clientCredentials"`
}

// ClusterInfo encapsulates the Kubernetes cluster information to be sent to App ID
type ClusterInfo struct {
	Name     string             `json:"name"`
	GUID     string             `json:"guid"`
	Type     string             `json:"type"`
	Location string             `json:"location"`
	Services map[string]Service `json:"services,string"`
}

// ClusterPolicies encapsulates the policies retrieved from App ID
type ClusterPolicies struct {
	Services map[string]Service
}

// Service encapsulates a Kubernetes Service
type Service struct {
	Name                string `json:"name"`
	Namespace           string `json:"namespace"`
	IsProtectionEnabled bool   `json:"protectionEnabled"`
}

// ClientCredentials encapsulates App ID instance credentials
type ClientCredentials struct {
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
	appidCfg := &AppIDConfig{}

	// Retrieve Environment Variables
	appidCfg.AppidURL = os.Getenv(appIDURL)
	appidCfg.AppidAPIKey = os.Getenv(appIDApiKey)
	clsterName := os.Getenv(clusterName)
	clsterGUID := os.Getenv(clusterGUID)
	clsterType := os.Getenv(clusterType)
	clsterLocation := os.Getenv(clusterLocation)

	log.Infof("APPID_URL: %s", appidCfg.AppidURL)
	log.Infof("APPID_APIKEY: %s", appidCfg.AppidAPIKey)
	log.Infof("CLUSTER_NAME: %s", clsterName)
	log.Infof("CLUSTER_TYPE: %s", clsterType)
	log.Infof("CLUSTER_LOCATION: %s", clsterLocation)
	log.Infof("CLUSTER_GUID: %s", clsterGUID)

	if appidCfg.AppidURL == "" || appidCfg.AppidAPIKey == "" || clsterName == "" || clsterGUID == "" || clsterLocation == "" || clsterType == "" {
		log.Errorf("Missing one of the following environment variables: APPID_URL APPID_APIKEY CLUSTER_NAME CLUSTER_GUID CLUSTER_LOCATION CLUSTER_TYPE")
		log.Error("Shutting down....")
		return nil, errors.New("Missing one or more env variables")
	}

	appidCfg.Port = defaultPort
	if len(os.Args) > 1 {
		appidCfg.Port = os.Args[1]
	}

	// Retrieve App ID instance configuration
	credentials, err := retrieveAppIDConfig(appidCfg.AppidURL, appidCfg.AppidAPIKey)
	if err != nil {
		log.Error("Shutting down....")
		return nil, errors.New("Could not retrieve App ID instance credentials")
	}

	appidCfg.ClientCredentials = credentials

	// Retrieve cluster configuration before monitoring. For the moment, this must succeed or services will be overwritten.
	//clusterInfo, err := retrieveClusterInfo(cfg.AppidURL, cfg.AppidAPIKey, clsterGUID)
	//if err != nil {
	//	log.Error("Shutting down....")
	//	return nil, errors.New("Could not retrieve cluster configuration from App ID")
	//} else if clusterInfo != nil {
	//	cfg.ClusterInfo = clusterInfo
	//} else {
	appidCfg.ClusterInfo = &ClusterInfo{
		Name:     clsterName,
		GUID:     clsterGUID,
		Type:     clsterType,
		Location: clsterLocation,
		Services: make(map[string]Service),
	}
	//}

	res, _ := json.MarshalIndent(appidCfg, "", "\t")
	log.Debugf("Retrieved configuration:\n %s", string(res))

	return appidCfg, nil
}

func retrieveAppIDConfig(url string, apiKey string) (*ClientCredentials, error) {
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

	appidCreds := ClientCredentials{}
	err = json.Unmarshal(body, &appidCreds)
	if err != nil {
		log.Errorf("<< retrieveAppIDConfig FAIL json.Unmarshal :: %s", err)
		return nil, err
	}
	log.Debugf("<< retrieveAppIDConfig OK")

	return &appidCreds, nil
}

func retrieveClusterInfo(url string, apiKey string, clusterID string) (*ClusterInfo, error) {
	log.Infof(">> retrieveClusterInfo")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", url+"/clusters/"+clusterID, nil)
	req.Header.Add("X-Api-Key", apiKey)
	if err != nil {
		log.Errorf("<< retrieveClusterInfo FAIL http.NewRequest :: %s", err)
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("<< retrieveClusterInfo FAIL client.Do :: %s", err)
		return nil, err
	}

	if resp.StatusCode == 403 {
		log.Error("<< retrieveClusterInfo 403")
		return nil, errors.New("403 Forbidden")
	}

	if resp.StatusCode == 404 {
		return nil, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	log.Debugf("retrieveClusterInfo Response body: %s", string(body))

	if err != nil {
		log.Errorf("<< retrieveClusterInfo FAIL ioutil.ReadAll :: %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	clusterInfo := ClusterInfo{}
	err = json.Unmarshal(body, &clusterInfo)
	if err != nil {
		log.Errorf("<< retrieveClusterInfo FAIL json.Unmarshal :: %s", err)
		return nil, err
	}
	log.Debugf("<< retrieveClusterInfo OK")

	if clusterInfo.Services == nil { // Can be removed when the API guarantees this is returned
		clusterInfo.Services = make(map[string]Service)
	}

	return &clusterInfo, nil
}

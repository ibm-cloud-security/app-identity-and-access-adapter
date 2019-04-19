package monitor

import (
	"encoding/json"
	"os"

	"istio.io/istio/pkg/log"
)

const (
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

	appidCfg.Port = defaultPort
	if len(os.Args) > 1 {
		appidCfg.Port = os.Args[1]
	}
	appidCfg.ClientCredentials = &ClientCredentials{
		TenantID:         "798288dc-79cb-4faf-9825-dad68cd4ed6f",
		ClientID:         "7a2a8cb8-774e-49e0-90c2-425f03aecec6",
		Secret:           "Y2VjNGIwNjctOTEyMy00NTQ0LTg0NjgtZTJjYTA3MjNhYjFl",
		AuthorizationURL: "https://appid-oauth.ng.bluemix.net/oauth/v3/798288dc-79cb-4faf-9825-dad68cd4ed6f/authorization",
		TokenURL:         "https://appid-oauth.ng.bluemix.net/oauth/v3/798288dc-79cb-4faf-9825-dad68cd4ed6f/token",
		UserinfoURL:      "https://appid-oauth.ng.bluemix.net/oauth/v3/798288dc-79cb-4faf-9825-dad68cd4ed6f/userinfo",
		JwksURL:          "https://appid-oauth.ng.bluemix.net/oauth/v3/798288dc-79cb-4faf-9825-dad68cd4ed6f/publicKeys",
	}

	appidCfg.ClusterInfo = &ClusterInfo{
		Services: make(map[string]Service),
	}

	res, _ := json.MarshalIndent(appidCfg, "", "\t")
	log.Debugf("Retrieved configuration:\n %s", string(res))

	return appidCfg, nil
}

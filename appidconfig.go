package ibmcloudappid

import (
	"errors"
	"flag"
	"fmt"
	"istio.io/istio/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
	"time"
)

const (
	APPID_URL            = "APPID_URL"
	APPID_APIKEY         = "APPID_APIKEY"
	APPID_OAUTHSERVERURL = "APPID_OAUTHSERVERURL"
	TENANT_ID            = "TENANT_ID"
	CLUSTER_NAME         = "CLUSTER_NAME"
	CLUSTER_GUID         = "CLUSTER_GUID"
	CLUSTER_TYPE         = "CLUSTER_TYPE"
	CLUSTER_LOCATION     = "CLUSTER_LOCATION"
	DEFAULT_PORT         = "47304"
	defaultPubkeysInterval = 60 * time.Minute
	minPubkeyInterval      = 60 * time.Minute
)

// AppIDConfig encapsulates REST server configuration parameters
type AppIDConfig struct {// structure should not be marshaled to JSON, not even using defaults
	OAuthServerURL      string `json:"-"`
	AppidURL            string `json:"-"`
	AppidAPIKey         string `json:"-"`
	TenantID            string `json:"-"`
	ClusterName         string `json:"-"`
	ClusterGUID         string `json:"-"`
	ClusterType         string `json:"-"`
	ClusterLocation     string `json:"-"`
	Port                string `json:"-"`
	IsProtectionEnabled bool   `json:"-"`
}

// NewAppIDConfig creates a configuration object
func NewAppIDConfig() (*AppIDConfig, error) {
	cfg := &AppIDConfig{}

	cfg.TenantID = os.Getenv(TENANT_ID)
	cfg.AppidURL = os.Getenv(APPID_URL)
	cfg.AppidAPIKey = os.Getenv(APPID_APIKEY)
	cfg.OAuthServerURL = os.Getenv(APPID_OAUTHSERVERURL)
	cfg.ClusterName = os.Getenv(CLUSTER_NAME)
	cfg.ClusterGUID = os.Getenv(CLUSTER_GUID)
	cfg.ClusterType = os.Getenv(CLUSTER_TYPE)
	cfg.ClusterLocation = os.Getenv(CLUSTER_LOCATION)

	log.Infof("TENANT_ID: %s", cfg.TenantID)
	log.Infof("APPID_URL: %s", cfg.AppidURL)
	log.Infof("APPID_APIKEY: %s", cfg.AppidAPIKey)
	log.Infof("CLUSTER_NAME: %s", cfg.ClusterName)
	log.Infof("CLUSTER_GUID: %s", cfg.ClusterGUID)
	log.Infof("CLUSTER_TYPE: %s", cfg.ClusterType)
	log.Infof("CLUSTER_LOCATION: %s", cfg.ClusterLocation)

	if cfg.AppidURL == "" || cfg.AppidAPIKey == "" || cfg.ClusterName == "" || cfg.ClusterGUID == "" || cfg.ClusterLocation == "" || cfg.TenantID == "" || cfg.ClusterType == "" {
		log.Errorf("Missing one of the following environment variables: APPID_URL APPID_APIKEY CLUSTER_NAME CLUSTER_GUID CLUSTER_LOCATION CLUSTER_TYPE")
		log.Error("Shutting down....")
		return nil, errors.New("Missing one or more env variables")
	}

	cfg.Port = DEFAULT_PORT
	if len(os.Args) > 1 {
		cfg.Port = os.Args[1]
	}

	return cfg, nil
}

func newKubeConfig() {
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	pods, err := clientset.CoreV1().Pods("default").List(metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))

	for pod := range pods.Items {
		fmt.Printf("There are %d pods in the cluster\n", pod)
	}
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

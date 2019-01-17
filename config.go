package ibmcloudappid

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"istio.io/istio/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	appIDURL               = "APPID_URL"
	appIDApiKey            = "APPID_APIKEY"
	oauthServerURL         = "APPID_OAUTHSERVERURL"
	tenantID               = "TENANT_ID"
	clusterName            = "CLUSTER_NAME"
	clusterGUID            = "CLUSTER_GUID"
	clusterType            = "CLUSTER_TYPE"
	clusterLocation        = "CLUSTER_LOCATION"
	defaultPort            = "47304"
	defaultPubkeysInterval = 60 * time.Minute
	minPubkeyInterval      = 60 * time.Minute
)

// Config encapsulates REST server configuration parameters
type Config struct { // structure should not be marshaled to JSON, not even using defaults
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

// NewConfig creates a configuration object
func NewConfig() (*Config, error) {
	cfg := &Config{}

	cfg.TenantID = os.Getenv(tenantID)
	cfg.AppidURL = os.Getenv(appIDURL)
	cfg.AppidAPIKey = os.Getenv(appIDApiKey)
	cfg.OAuthServerURL = os.Getenv(oauthServerURL)
	cfg.ClusterName = os.Getenv(clusterName)
	cfg.ClusterGUID = os.Getenv(clusterGUID)
	cfg.ClusterType = os.Getenv(clusterType)
	cfg.ClusterLocation = os.Getenv(clusterLocation)

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

	cfg.Port = defaultPort
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

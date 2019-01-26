package ibmcloudappid

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"istio.io/istio/pkg/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	duration = time.Millisecond * 1000
)

// Monitor tracks kubernetes data with App ID
type Monitor interface {
	Start()
	Stop() error
}

type defaultMonitor struct {
	cfg    *AppIDConfig
	ticker *time.Ticker
}

// NewMonitor creates an App ID Monitor object
func NewMonitor(cfg *AppIDConfig) (Monitor, error) {
	monitor := &defaultMonitor{
		ticker: time.NewTicker(time.Millisecond * 1000),
		cfg:    cfg,
	}

	go monitor.watchServices(cfg)

	go func() {
		for range monitor.ticker.C {
			monitor.registerCluster()
		}
	}()

	return monitor, nil
}

/// Starts the App ID Monitoring Service
func (m *defaultMonitor) Start() {
	if m != nil {
		m.ticker.Stop()
	}
	m.ticker = time.NewTicker(time.Millisecond * 1000)

	go func() {
		for range m.ticker.C {
			m.registerCluster()
		}
	}()
}

/// Starts the App ID Monitoring Service
func (m *defaultMonitor) Stop() error {
	if m != nil {
		m.ticker.Stop()
		return nil
	}
	return errors.New("Missing active ticker")
}

func (m *defaultMonitor) registerCluster() {
	requestURL := m.cfg.AppidURL + "/clusters"
	log.Infof(">> registerCluster :: clusterGuid %s, requestUrl %s", m.cfg.ClusterInfo.GUID, requestURL)

	jsonString, _ := json.Marshal(m.cfg.ClusterInfo)

	response, err := http.Post(requestURL, "application/json", bytes.NewBuffer(jsonString))
	if err != nil {
		log.Errorf("Error sending request to App ID management: %s", err)
		return
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Error reading App ID management response: %s", err)
		return
	}

	clusterInfo := ClusterInfo{}
	err = json.Unmarshal(body, &clusterInfo)
	if err != nil {
		log.Errorf("Error parsing management cluster response: %s", err)
		return
	}

	m.cfg.ClusterPolicies = &ClusterPolicies{
		Services: clusterInfo.Services,
	}
	log.Infof(">> registerCluster :: Updated m.cfg.ClusterPolicies %v", m.cfg.ClusterPolicies)
}

func (m *defaultMonitor) watchServices(cfg *AppIDConfig) {

	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("Error creating a cluster config: %s", err)
		return
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("Error creating a client set: %s", err)
		return
	}

	// Watch for service changes
	watchlist := cache.NewListWatchFromClient(clientset.Core().RESTClient(), "services", v1.NamespaceAll, fields.Everything())
	_, controller := cache.NewInformer(
		watchlist,
		&v1.Service{},
		time.Second*0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if service := checkValidService(obj); service != nil {
					// If the element is not already in our table Add it.
					if _, ok := m.cfg.ClusterInfo.Services[service.Name+"."+service.Namespace]; !ok {
							m.cfg.ClusterInfo.Services[service.Name+"."+service.Namespace] = Service{
							Name:                service.Name,
							Namespace:           service.Namespace,
							// Adapter should not be able to decide whether protection is on or off.
							// Need to fix this in the mgmt API as well
							//IsProtectionEnabled: false,
						}
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if service := checkValidService(obj); service != nil {
					delete(m.cfg.ClusterInfo.Services, service.Name+"."+service.Namespace)
				}
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
}

func checkValidService(obj interface{}) *v1.Service {
	service, ok := obj.(*v1.Service)
	if !ok {
		log.Errorf("Could not cast interface as Service")
		return nil
	}

	// Ensure service does not belong to system or kube namespaces
	if strings.HasPrefix(service.Namespace, "kube") || strings.HasSuffix(service.Namespace, "system") || strings.Contains(service.Name, "demo-cloud-fund-web") {
		log.Debugf("System or kubernetes service - %s : %s", service.Namespace, service.Name)
		return nil
	}

	return service
}

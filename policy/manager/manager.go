// Package manager is responsible for monitoring and maintaining authn/z policies
package manager

import (
	"istio.io/istio/mixer/adapter/ibmcloudappid/authserver/keyset"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"istio.io/istio/mixer/adapter/ibmcloudappid/authserver"
	c "istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"istio.io/istio/mixer/adapter/ibmcloudappid/pkg/apis/policies/v1"
	policiesClientSet "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/client/clientset/versioned"
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy"
	policyController "istio.io/istio/mixer/adapter/ibmcloudappid/policy/controller"
	policyHandler "istio.io/istio/mixer/adapter/ibmcloudappid/policy/handler"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

// PolicyManager is responsible for storing and managing policy/client data
type PolicyManager interface {
	Evaluate(*authorization.ActionMsg) Action
}

// Manager is responsible for storing and managing policy/client data
type Manager struct {
	kube      kubernetes.Interface
	clientset policiesClientSet.Interface
	// clients maps client_name -> client_config
	clients map[string]*c.Client
	// authserver maps jwksurl -> AuthorizationServers
	authservers map[string]authserver.AuthorizationServer
	// policies maps endpoint -> list of policies
	apiPolicies map[endpoint][]v1.JwtPolicySpec
	// policies maps endpoint -> list of policies
	webPolicies map[endpoint][]v1.OidcPolicySpec
}

// Action encapsulates information needed to begin executing a policy
type Action struct {
	Type     policy.Type
	policies []PolicyAction
}

type PolicyAction struct {
	KeySet keyset.KeySet
	// Rule []Rule
}

type endpoint struct {
	namespace, service, path, method string
}

// Evaluate makes authn/z decision based on authorization action
// being performed.
func (m *Manager) Evaluate(action *authorization.ActionMsg) Action {
	// Get destination service
	destinationService := strings.TrimSuffix(action.Service, "."+action.Namespace+".svc.cluster.local")

	ep := endpoint{
		namespace: action.Namespace,
		service:   destinationService,
		path:      action.Path,
		method:    action.Method,
	}

	apiPolicies := m.apiPolicies[ep]
	webPolicies := m.webPolicies[ep]
	if (webPolicies == nil || len(webPolicies) == 0) && (apiPolicies == nil || len(apiPolicies) == 0) {
		return Action{
			Type: policy.NONE,
		}
	}

	if (webPolicies != nil && len(webPolicies) >= 0) && (apiPolicies != nil && len(apiPolicies) > 0) {
		// Make decision
		return Action{
			Type: policy.NONE,
		}
	}

	if webPolicies != nil && len(webPolicies) >= 0 {
		// Make decision
		return m.GetWebStrategyAction(webPolicies)
	}

	return m.GetAPIStrategyAction(apiPolicies)
}

func (m *Manager) GetAPIStrategyAction(policies []v1.JwtPolicySpec) Action {
	return Action{
		Type: policy.API,
		policies: []PolicyAction{
			PolicyAction{
				KeySet: m.AuthServer(policies[0].JwksURL).KeySet(),
			},
		},
	}
}

func (m *Manager) GetWebStrategyAction(policies []v1.OidcPolicySpec) Action {
	return Action{
		Type: policy.WEB,
		policies: []PolicyAction{
			PolicyAction{
				KeySet: m.Client(policies[0].ClientName).AuthServer.KeySet(),
			},
		},
	}
}

// Client returns the client instance given its name
func (m *Manager) Client(clientName string) *c.Client {
	return m.clients[clientName]
}

// AuthServer returns the client instance given its name
func (m *Manager) AuthServer(jwksurl string) authserver.AuthorizationServer {
	return m.authservers[jwksurl]
}

// New creates a PolicyManager
func New() PolicyManager {
	return &Manager{
		clients:     make(map[string]*c.Client),
		authservers: make(map[string]authserver.AuthorizationServer),
		apiPolicies: make(map[endpoint][]v1.JwtPolicySpec),
		webPolicies: make(map[endpoint][]v1.OidcPolicySpec),
	}
}

// retrieve the Kubernetes cluster client from outside of the cluster
func getKubernetesClient() (kubernetes.Interface, policiesClientSet.Interface) {
	// construct the path to resolve to `~/.kube/config`
	kubeConfigPath := os.Getenv("HOME") + "/.kube/config"

	// create the config from the path
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	// generate the client based off of the config
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	policiesClient, err := policiesClientSet.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	log.Info("Successfully constructed k8s client")
	return client, policiesClient
}

func (m *Manager) initPolicyController(informer cache.SharedIndexInformer, client kubernetes.Interface) {
	// create a new queue so that when the informer gets a resource that is either
	// a result of listing or watching, we can add an idenfitying key to the queue
	// so that it can be handled in the handler

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	// add event handlers to handle the three types of events for resources:
	//  - adding new resources
	//  - updating existing resources
	//  - deleting resources
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// convert the resource object into a key (in this case
			// we are just doing it in the format of 'namespace/name')
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debugf("Add myresource: %s", key)
			if err == nil {
				// add the key to the queue for the handler to get
				queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			log.Debugf("Update myresource: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// DeletionHandlingMetaNamsespaceKeyFunc is a helper function that allows
			// us to check the DeletedFinalStateUnknown existence in the event that
			// a resource was deleted but it is still contained in the index
			//
			// this then in turn calls MetaNamespaceKeyFunc
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			log.Debugf("Delete myresource: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
	})

	// construct the Controller object which has all of the necessary components to
	// handle logging, connections, informing (listing and watching), the queue,
	// and the handler
	controller := policyController.Controller{
		Clientset: client,
		Informer:  informer,
		Queue:     queue,
		Handler:   &policyHandler.PolicyHandler{},
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	// run the controller loop to process items
	go controller.Run(stopCh)

	// use a channel to handle OS signals to terminate and gracefully shut
	// down processing
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm
}

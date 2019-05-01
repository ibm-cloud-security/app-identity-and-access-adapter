package initializer

import (
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"

	policiesClientSet "ibmcloudappid/adapter/pkg/client/clientset/versioned"
	policiesInformer "ibmcloudappid/adapter/pkg/client/informers/externalversions"
	policyController "ibmcloudappid/adapter/policy/controller"
	"ibmcloudappid/adapter/policy/manager"
	"istio.io/istio/pkg/log"
)

// Initializer interface contains the methods that are required
type Initializer interface {
	GetManager() manager.PolicyManager
}

type PolicyInitializer struct {
	Manager manager.PolicyManager
}

func (pi *PolicyInitializer) GetManager() manager.PolicyManager {
	return pi.Manager
}

func New() (Initializer, error) {
	policyManager := manager.New()
	policyInitializer := &PolicyInitializer{policyManager}

	client, myresourceClient, err := getKubernetesClient()
	if err != nil {
		return nil, err
	}
	informerlist := policiesInformer.NewSharedInformerFactory(myresourceClient, 0)
	go initPolicyController(informerlist.Appid().V1().JwtPolicies().Informer(), client, policyInitializer.Manager)
	go initPolicyController(informerlist.Appid().V1().OidcPolicies().Informer(), client, policyInitializer.Manager)
	go initPolicyController(informerlist.Appid().V1().OidcClients().Informer(), client, policyInitializer.Manager)

	return policyInitializer, nil
}

// Get remote or local kube config
func getKubeConfig() (*rest.Config, error) {

	// attempt to create an the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Error("Error creating a in-cluster config. Attempting local config...")

		// attempt to create a local config client
		kubeConfigPath := os.Getenv("HOME") + "/.kube/config"

		// create the config from the path
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
		if err != nil {
			log.Errorf("Could not create local config: %v", err)
			return nil, err
		}
	}

	return config, nil
}

// retrieve the Kubernetes cluster client from outside of the cluster
func getKubernetesClient() (kubernetes.Interface, policiesClientSet.Interface, error) {

	config, err := getKubeConfig()
	if err != nil {
		log.Fatalf("Error creating a cluster config: %s", err)
		return nil, nil, err
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating a client set: %s", err)
		return nil, nil, err
	}

	policiesClient, err := policiesClientSet.NewForConfig(config)
	if err != nil {
		log.Fatalf("NewForConfig: %v", err)
		return nil, nil, err
	}

	log.Info("Successfully constructed k8s client")
	return client, policiesClient, nil
}

func initPolicyController(informer cache.SharedIndexInformer, client kubernetes.Interface, policyManager manager.PolicyManager) {
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
		Handler:   policyManager,
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

package initializer

import (
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"os"
	"os/signal"
	"syscall"

	manager "istio.io/istio/mixer/adapter/ibmcloudappid/policy/manager"
	"k8s.io/client-go/kubernetes"

	policiesClientSet "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/client/clientset/versioned"
	policiesInformer "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/client/informers/externalversions"
	policyController "istio.io/istio/mixer/adapter/ibmcloudappid/policy/controller"
	policyHandler "istio.io/istio/mixer/adapter/ibmcloudappid/policy/handler"
	"istio.io/istio/pkg/log"
)

// Handler interface contains the methods that are required
type Initializer interface {}

type PolicyInitializer struct{
	Manager manager.PolicyManager
}


func New() Initializer {
	policyManager := manager.New();
	policyInitializer := &PolicyInitializer{ policyManager}

	client, myresourceClient := getKubernetesClient()
	informerlist := policiesInformer.NewSharedInformerFactory(myresourceClient, 0)
	initPolicyController(informerlist.Appid().V1().JwtPolicies().Informer(), client, policyInitializer.Manager)
	initPolicyController(informerlist.Appid().V1().OidcPolicies().Informer(), client, policyInitializer.Manager)
	initPolicyController(informerlist.Appid().V1().OidcClients().Informer(), client, policyInitializer.Manager)

	return policyInitializer
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
		Handler:   &policyHandler.PolicyHandler{policyManager},
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

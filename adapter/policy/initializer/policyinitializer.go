package initializer

import (
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"

	v1 "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/apis/policies/v1"
	policiesClientSet "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/client/clientset/versioned"
	policiesInformer "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/pkg/client/informers/externalversions"
	policyController "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/controller"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/handler"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
)

// Initializer interface contains the methods that are required
type Initializer interface {
	GetHandler() handler.PolicyHandler
	GetKubeClient() kubernetes.Interface
}

type PolicyInitializer struct {
	KubeClient kubernetes.Interface
	Handler    handler.PolicyHandler
}

func (pi *PolicyInitializer) GetKubeClient() kubernetes.Interface {
	return pi.KubeClient
}

func (pi *PolicyInitializer) GetHandler() handler.PolicyHandler {
	return pi.Handler
}

func New(store policy.PolicyStore) (Initializer, error) {
	client, myresourceClient, err := getKubernetesClient()
	if err != nil {
		return nil, err
	}

	handler := handler.New(store, client)
	policyInitializer := &PolicyInitializer{Handler: handler, KubeClient: client}
	informerlist := policiesInformer.NewSharedInformerFactory(myresourceClient, 0)

	go initPolicyController(informerlist.Appid().V1().JwtConfigs().Informer(), client, policyInitializer.Handler, v1.JWTCONFIG)
	go initPolicyController(informerlist.Appid().V1().OidcConfigs().Informer(), client, policyInitializer.Handler, v1.OIDCCONFIG)
	go initPolicyController(informerlist.Appid().V1().Policies().Informer(), client, policyInitializer.Handler, v1.POLICY)

	return policyInitializer, nil
}

// Get remote or local kube config
func getKubeConfig() (*rest.Config, error) {

	// attempt to create an the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		zap.L().Warn("Error creating an in-cluster config. Attempting local config...", zap.Error(err))

		// attempt to create a local config client
		kubeConfigPath := os.Getenv("KUBECONFIG")
		if kubeConfigPath != "" {
			zap.L().Info("Using KubeConfig : " + kubeConfigPath)
		} else {
			zap.L().Info("Attempting to use minikube : " + os.Getenv("HOME"))
			kubeConfigPath = os.Getenv("HOME") + "/.kube/config"
		}

		// create the config from the path
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
		if err != nil {
			zap.L().Error("Could not create local config", zap.Error(err))
			return nil, err
		}
	}

	return config, nil
}

// retrieve the Kubernetes cluster client from outside of the cluster
func getKubernetesClient() (kubernetes.Interface, policiesClientSet.Interface, error) {

	config, err := getKubeConfig()
	if err != nil {
		zap.L().Fatal("Error creating a cluster config", zap.Error(err))
		return nil, nil, err
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		zap.L().Fatal("Error creating a client set", zap.Error(err))
		return nil, nil, err
	}

	policiesClient, err := policiesClientSet.NewForConfig(config)
	if err != nil {
		zap.L().Fatal("Error creating a NewForConfig", zap.Error(err))
		return nil, nil, err
	}

	zap.L().Info("Successfully constructed k8s client")
	return client, policiesClient, nil
}

func initPolicyController(informer cache.SharedIndexInformer, client kubernetes.Interface, policyHandler handler.PolicyHandler, crdType v1.CrdType) {
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
			zap.L().Debug("Adding resource", zap.String("key", key))
			if err == nil {
				// add the key to the queue for the handler to get
				queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			zap.L().Debug("Updating resource", zap.String("key", key))
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
			zap.L().Debug("Delete resource", zap.String("key", key))
			if err == nil {
				queue.Add(key)
			}
		},
	})

	// construct the Controller object which has all of the necessary components to
	// handle logging, connections, informing (listing and watching), the queue,
	// and the handler
	controller := policyController.Controller{
		CrdType:   crdType,
		Clientset: client,
		Informer:  informer,
		Queue:     queue,
		Handler:   policyHandler,
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

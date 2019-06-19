// Package handler is responsible for monitoring and maintaining authn/z policies
package handler

import (
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/handler/crdeventhandler"
	policystore "github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)

// PolicyHandler is responsible for storing and managing policy/client data
type PolicyHandler interface {
	HandleAddUpdateEvent(obj interface{})
	HandleDeleteEvent(obj interface{})
}

// CrdHandler is responsible for storing and managing policy/client data
type CrdHandler struct {
	store      policystore.PolicyStore
	kubeClient kubernetes.Interface
}

// //////////////// constructor //////////////////

// New creates a PolicyManager
func New(store policystore.PolicyStore, kubeClient kubernetes.Interface) PolicyHandler {
	return &CrdHandler{
		store:      store,
		kubeClient: kubeClient,
	}
}

// //////////////// interface //////////////////

// HandleAddUpdateEvent updates the store after a CRD has been added
func (c *CrdHandler) HandleAddUpdateEvent(obj interface{}) {
	crdhandler := crdeventhandler.GetAddEventHandler(obj, c.store, c.kubeClient)
	if crdhandler != nil {
		crdhandler.HandleAddUpdateEvent()
	}
}

// HandleDeleteEvent updates the store after a CRD has been deleted
func (c *CrdHandler) HandleDeleteEvent(obj interface{}) {
	crdKey, ok := obj.(policy.CrdKey)
	if !ok {
		zap.L().Warn("Expected to receive CrdKey from Kubernetes informer")
		return
	}
	zap.S().Debugf("crdKey : %s", crdKey.Id)
	zap.S().Debugf("crdType : %s", crdKey.CrdType)
	handler := crdeventhandler.GetDeleteEventHandler(crdKey, c.store)
	if handler != nil {
		handler.HandleDeleteEvent()
	}
}
package handler

import (
	"ibmcloudappid/policy/manager"
	"istio.io/istio/pkg/log"
)

// Handler interface contains the methods that are required
type Handler interface {
	Init() error
	ObjectCreated(obj interface{})
	ObjectDeleted(obj interface{})
	ObjectUpdated(objOld, objNew interface{})
}

type PolicyHandler struct{
	Manager manager.PolicyManager
}

// Init handles any handler initialization
func (t *PolicyHandler) Init() error {
	log.Debug("TestHandler.Init")
	return nil
}

// ObjectCreated is called when an object is created
func (t *PolicyHandler) ObjectCreated(obj interface{}) {
	log.Debug("TestHandler.ObjectCreated")
	t.Manager.HandleAddEvent(obj)
	log.Debug("TestHandler.ObjectCreated done")
}

// ObjectDeleted is called when an object is deleted
func (t *PolicyHandler) ObjectDeleted(obj interface{}) {
	log.Debug("TestHandler.ObjectDeleted")
	t.Manager.HandleDeleteEvent(obj)
	log.Debug("TestHandler.ObjectDeleted done")
}

// ObjectUpdated is called when an object is updated
func (t *PolicyHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Debug("TestHandler.ObjectUpdated")
}

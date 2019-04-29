package handler

import (
	"istio.io/istio/pkg/log"
	v1 "istio.io/istio/mixer/adapter/ibmcloudappid/pkg/apis/policies/v1"
)

// Handler interface contains the methods that are required
type Handler interface {
	Init() error
	ObjectCreated(obj interface{})
	ObjectDeleted(obj interface{})
	ObjectUpdated(objOld, objNew interface{})
}

type PolicyHandler struct{}

// Init handles any handler initialization
func (t *PolicyHandler) Init() error {
	log.Debug("TestHandler.Init")
	return nil
}

// ObjectCreated is called when an object is created
func (t *PolicyHandler) ObjectCreated(obj interface{}) {
	switch obj.(type){
	case *v1.JwtPolicy:
		log.Debug("TestHandler.ObjectCreated : *v1.JwkPolicy")
		jwk := obj.(*v1.JwtPolicy)
		log.Debugf("%r", jwk)
		log.Debug("TestHandler.ObjectCreated JwkPolicy done---------")
	case *v1.OidcPolicy:
		log.Debug("TestHandler.ObjectCreated : *v1.OidcPolicy")
		oidc := obj.(*v1.OidcPolicy)
		log.Debugf("%r", oidc)
		log.Debug("TestHandler.ObjectCreated OidcPolicy done---------")
	case *v1.OidcClient:
		log.Debug("TestHandler.ObjectCreated : *v1.OidcClient")
		client := obj.(*v1.OidcClient)
		log.Debugf("%r", client)
		log.Debug("TestHandler.ObjectCreated OidcClient done---------")
	default :
		log.Error("Unknown Object")
	}
}

// ObjectDeleted is called when an object is deleted
func (t *PolicyHandler) ObjectDeleted(obj interface{}) {
	log.Debug("TestHandler.ObjectDeleted")
}

// ObjectUpdated is called when an object is updated
func (t *PolicyHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Debug("TestHandler.ObjectUpdated")
}

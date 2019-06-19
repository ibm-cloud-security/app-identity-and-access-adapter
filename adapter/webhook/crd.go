package webhook

import (
	"net/http"

	"go.uber.org/zap"
	"k8s.io/api/admission/v1beta1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)


type Crdhandler struct {
	store policy.PolicyStore
}

// ServeHTTP handles the http portion of a request prior to handing to an admit
// function
func (handler Crdhandler) Serve(w http.ResponseWriter, r *http.Request) {
	ServeHTTP(w, r, Admit)
}

// This function expects all CRDs submitted to it to be apiextensions.k8s.io/v1beta1
// TODO: When apiextensions.k8s.io/v1 is added we will need to update this function.
func Admit(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	zap.L().Info("admitting crd")
	_ = metav1.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1beta1", Resource: "customresourcedefinitions"}
	/*if ar.Request.Resource != crdResource {
		err := fmt.Errorf("expect resource to be %s", crdResource)
		zap.L().Error("GroupVersionResource Error: ", zap.Error(err))
		return toAdmissionResponse(err)
	}*/

	raw := ar.Request.Object.Raw
	crd := apiextensionsv1beta1.CustomResourceDefinition{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &crd); err != nil {
		zap.L().Error("deserializer error: ", zap.Error(err))
		return toAdmissionResponse(err)
	}
	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	/*if v, ok := crd.Labels["webhook-e2e-test"]; ok {
		if v == "webhook-disallow" {
			reviewResponse.Allowed = false
			reviewResponse.Result = &metav1.Status{Message: "the crd contains unwanted label"}
		}
	}*/
	return &reviewResponse
}
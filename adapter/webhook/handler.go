package webhook

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"

	"go.uber.org/zap"

	"net/http"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store/policy"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
)

// admitFunc is the type we use for all of our validators
type admitFunc func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

type Webhook interface {
	Serve(w http.ResponseWriter, r *http.Request)
}

type Webhookhandler struct {
	store policy.PolicyStore
	Webhook
}

// ServeHTTP handles the http portion of a request prior to handing to an admit
// function
func ServeHTTP(w http.ResponseWriter, r *http.Request, admit admitFunc) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		zap.S().Errorf("contentType=%s, expect application/json", contentType)
		return
	}
	zap.L().Info("handling request: ", zap.ByteString("body", body))

	// The AdmissionReview that was sent to the webhook
	requestedAdmissionReview := v1beta1.AdmissionReview{}

	// The AdmissionReview that will be returned
	responseAdmissionReview := v1beta1.AdmissionReview{}

	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &requestedAdmissionReview); err != nil {
		zap.L().Error("Error in  server : ", zap.Error(err))
		responseAdmissionReview.Response = toAdmissionResponse(err)
	} else {
		// pass to admitFunc
		responseAdmissionReview.Response = admit(requestedAdmissionReview)
	}

	// Return the same UID
	responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
	zap.S().Infof("sending response:  %v", responseAdmissionReview.Response)
	//klog.V(2).Info(fmt.Sprintf("sending response: %v", responseAdmissionReview.Response))

	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		zap.L().Error("Marshal Error: ", zap.Error(err))
	}
	if _, err := w.Write(respBytes); err != nil {
		zap.L().Error("Write response Error: ", zap.Error(err))
	}
}

// toAdmissionResponse is a helper function to create an AdmissionResponse
// with an embedded error
func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func NewWebhookServer(store policy.PolicyStore, port string, tlscert string, tlskey string) (*http.Server, error) {
	server, err := NewWebhookServerNoSSL(store, port)

	if err != nil {
		return server, err
	}

	sCert, err := tls.LoadX509KeyPair(tlscert, tlskey)

	if err != nil {
		return server, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{sCert},
	}
	server.TLSConfig = tlsConfig
	server.Addr = ":" + port
	return server, nil
}

func NewWebhookServerNoSSL(store policy.PolicyStore, port string) (*http.Server, error) {
	if store == nil {
		zap.L().Error("Trying to create webhookhandler, but no store provided.")
		return nil, errors.New("could not create webhook handler using undefined store")
	}
	server := &http.Server{
		Addr:  ":" + port,
	}
	http.HandleFunc("/validatecrd", Crdhandler{store: store}.Serve)
	return server, nil
}
// nolint:lll
// Generates the mygrpcadapter adapter's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/ibmcloudappid/config/config.proto -x "-s=false -n ibmcloudappid -t authorization"

package ibmcloudappid

import (
	"context"
	"fmt"
	"net"
	"google.golang.org/grpc"

	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/adapter/ibmcloudappid/config"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run(shutdown chan error)
	}

	// AppidAdapter supports metric template.
	AppidAdapter struct {
		listener net.Listener
		server   *grpc.Server
	}
)

var IsProtectionEnabled = false

var _ authorization.HandleAuthorizationServiceServer = &AppidAdapter{}

// HandleMetric records metric entries
func (s *AppidAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Infof(">> HandleAuthorization :: received request %v\n", *r)

	if (!IsProtectionEnabled){
		log.Infof("Application protection disabled")
		return &v1beta1.CheckResult{
			Status: status.OK,
		}, nil

	}

	cfg := &config.Params{}

	if r.AdapterConfig != nil {
		if err := cfg.Unmarshal(r.AdapterConfig.Value); err != nil {
			log.Errorf("error unmarshalling adapter config: %v", err)
			return nil, err
		}
	}

	appidUrl := cfg.AppidUrl
	log.Infof(">> HandleAuthorization :: appidUrl to check :: %s", appidUrl)

	log.Infof(">> HandleAuthorization :: decoding values")
	decodeValue := func(in interface{}) interface{} {
		switch t := in.(type) {
		case *policy.Value_StringValue:
			return t.StringValue
		case *policy.Value_Int64Value:
			return t.Int64Value
		case *policy.Value_DoubleValue:
			return t.DoubleValue
		default:
			return fmt.Sprintf("%v", in)
		}
	}

	log.Infof(">> HandleAuthorization :: decoding values map")
	decodeValueMap := func(in map[string]*policy.Value) map[string]interface{} {
		out := make(map[string]interface{}, len(in))
		for k, v := range in {
			out[k] = decodeValue(v.GetValue())
		}
		return out
	}

	props := decodeValueMap(r.Instance.Subject.Properties)
	log.Infof(">> HandleAuthorization :: Received properties: %v", props)

	for k, v := range props {
		log.Infof(">> HandleAuthorization :: Received properties: key=%s value=%s", k, v)
		//fmt.Println("k:", k, "v:", v)
		if (k == "authorization_header") && v != "" {
			log.Infof("Got the right header!")
			return &v1beta1.CheckResult{
				Status: status.OK,
			}, nil
		}
	}

	log.Infof("failure; header not provided")
	return &v1beta1.CheckResult{
		Status: status.WithPermissionDenied("Unauthorized..."),
	}, nil
}

// Addr returns the listening address of the server
func (s *AppidAdapter) Addr() string {
	return s.listener.Addr().String()
}

// Run starts the server run
func (s *AppidAdapter) Run(shutdown chan error) {
	shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *AppidAdapter) Close() error {
	if s.server != nil {
		s.server.GracefulStop()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	return nil
}

// NewAppidAdapter creates a new IBP adapter that listens at provided port.
func NewAppidAdapter(port string) (Server, error) {

	if port == "" {
		port = "47304"
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Errorf("unable to listen on socket: %v", err)
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}
	s := &AppidAdapter{
		listener: listener,
	}

	log.Infof("listening on \"%v\"\n", s.Addr())

	s.server = grpc.NewServer()
	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)
	return s, nil
}

func SetIsProtectionEnabled (){

}
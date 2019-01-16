// nolint:lll
// Generates the appidadpater's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/ibmcloudappid/config/config.proto -x "-s=false -n ibmcloudappid -t authorization"

package ibmcloudappid

import (
	"context"
	"crypto"
	"fmt"
	"net"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/adapter/ibmcloudappid/config"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/pkg/log"
)

const (
	authorizationHeader = "authorization_header"
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
		listener     net.Listener
		server       *grpc.Server
		appIDPubkeys map[string]crypto.PublicKey
		cfg          *Config
	}
)

var _ authorization.HandleAuthorizationServiceServer = &AppidAdapter{}

// HandleAuthorization handles web authentiation
func (s *AppidAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Infof(">> HandleAuthorization :: received request %v\n", *r)

	if !s.cfg.IsProtectionEnabled {
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

	// Check whether we should perform API or Web strategy. Only API strategy is supported
	var useAPIStrategy = true
	if useAPIStrategy {
		return s.appIDAPIStrategy(r)
	}

	return s.appIDAPIStrategy(r)
}

func decodeValueMap(in map[string]*policy.Value) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = decodeValue(v.GetValue())
	}
	return out
}

func decodeValue(in interface{}) interface{} {
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
func NewAppidAdapter(cfg *Config) (Server, error) {

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Port))
	if err != nil {
		log.Errorf("unable to listen on socket: %v", err)
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}
	s := &AppidAdapter{
		listener: listener,
	}

	log.Infof("listening on \"%v\"\n", s.Addr())
	log.Infof("CREATING WITH CONFIG %s", cfg.ClusterName)
	s.cfg = cfg
	s.server = grpc.NewServer()
	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)

	// Retrieve the public keys which are used to verify the tokens
	for i := 0; i < 5; i++ {
		if err = s.getPubKeys(); err != nil {
			glog.Warningf("Failed to get Public Keys. Assuming failure is temporary, will retry later...")
			glog.Error(err.Error())
			if i == 4 {
				glog.Errorf("Unable to Obtain Public Keys after multiple attempts. Please restart the Ingress Pods.")
			}
		} else {
			glog.Infof("Success. Public Keys Obtained...")
			break
		}
	}

	return s, nil
}

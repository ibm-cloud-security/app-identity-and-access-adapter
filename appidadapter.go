// nolint:lll
// Generates the appidadpater's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/ibmcloudappid/config/config.proto -x "-s=false -n ibmcloudappid -t authorization"

package ibmcloudappid

import (
	"context"
	"fmt"
	"istio.io/istio/mixer/pkg/status"
	"net"
	"strings"

	"google.golang.org/grpc"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/adapter/ibmcloudappid/config"
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

	// AppidAdapter supports authorization template.
	AppidAdapter struct {
		listener net.Listener
		server   *grpc.Server
		cfg      *AppIDConfig
		parser   JWTTokenParser
		keyUtil  PublicKeyUtil
	}
)

var _ authorization.HandleAuthorizationServiceServer = &AppidAdapter{}

// HandleAuthorization handles web authentiation
func (s *AppidAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Infof(">> HandleAuthorization :: received request %v\n", *r)

	//if !s.cfg.ClusterInfo.IsProtectionEnabled {
	//	log.Infof("Application protection disabled")
	//	return &v1beta1.CheckResult{
	//		Status: status.OK,
	//	}, nil
	//}

	cfg := &config.Params{}

	if r.AdapterConfig != nil {
		if err := cfg.Unmarshal(r.AdapterConfig.Value); err != nil {
			log.Errorf("Error unmarshalling adapter config: %v", err)
			return nil, err
		}
	}

	//logEnvVars(r)

	props := decodeValueMap(r.Instance.Subject.Properties)
	destinationService := strings.TrimSuffix(props["destination_service_host"].(string), ".svc.cluster.local");
	clusterServices := s.cfg.ClusterPolicies.Services

	if clusterServices[destinationService].IsProtectionEnabled == true {
		log.Infof("Protected destination_service: %s ", destinationService);
		return s.appIDAPIStrategy(r)
	} else {
		log.Infof("Unprotected destination_service: %s ", destinationService);
		return &v1beta1.CheckResult{
			Status: status.OK,
		}, nil
	}
}

func logEnvVars(r *authorization.HandleAuthorizationRequest) {
	props := decodeValueMap(r.Instance.Subject.Properties)
	for key, val := range props {
		log.Infof("ENV:\n\tkey: %s\nvalue: \t%s", key, val)
	}
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
	case *policy.Value_IpAddressValue:
		return t.IpAddressValue
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

// NewAppIDAdapter creates a new AppID Adapter that listens at provided port.
func NewAppIDAdapter(cfg *AppIDConfig) (Server, error) {

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Port))
	if err != nil {
		log.Errorf("unable to listen on socket: %v", err)
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}
	s := &AppidAdapter{
		listener: listener,
		parser:   &defaultJWTParser{},
		keyUtil:  NewPublicKeyUtil(cfg.ClientCredentials.JwksURL),
		cfg:      cfg,
		server:   grpc.NewServer(),
	}

	log.Infof("listening on \"%v\"\n", s.Addr())

	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)

	return s, nil
}

// nolint:lll
// Generates the appidadpater's resource yaml. It contains the adapter's configuration, name, supported template
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
	"istio.io/istio/mixer/adapter/ibmcloudappid/keyutil"
	"istio.io/istio/mixer/adapter/ibmcloudappid/monitor"
	apistrategy "istio.io/istio/mixer/adapter/ibmcloudappid/strategy/api"
	"istio.io/istio/mixer/adapter/ibmcloudappid/validator"
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
		cfg      *monitor.AppIDConfig
		parser   validator.TokenValidator
		keyUtil  keyutil.KeyUtil
	}
)

var _ authorization.HandleAuthorizationServiceServer = &AppidAdapter{}

////////////////// adapter.Handler //////////////////////////

// HandleAuthorization evaulates authoroization policy using api/web strategy
func (s *AppidAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Infof("HandleAuthorization :: received request %v\n", *r)

	logInstanceVars(r)

	// Enforce policy
	api, err := apistrategy.New(*s.cfg, s.parser, s.keyUtil)
	if err != nil {
		return nil, err
	}

	return api.HandleAuthorizationRequest(r)
}

////////////////// server //////////////////////////

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

////////////////// constructor //////////////////////////

// NewAppIDAdapter creates a new App ID Adapter listening on the provided port.
func NewAppIDAdapter() (Server, error) {

	// Ensure we have correct configuration
	cfg, err := monitor.NewAppIDConfig()
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.Port))
	if err != nil {
		log.Errorf("Unable to listen on socket: %v", err)
		return nil, fmt.Errorf("Unable to listen on socket: %v", err)
	}

	// Start communication with App ID
	/*
		monitor, err := ibmcloudappid.NewMonitor(cfg)
		if err != nil {
			log.Errorf("Failed to create ibmcloudappid.NewMonitor: %s", err)
			os.Exit(-1)
		}
		monitor.Start()
	*/

	s := &AppidAdapter{
		listener: listener,
		parser:   validator.New(),
		keyUtil:  keyutil.New(cfg.ClientCredentials.JwksURL),
		cfg:      cfg,
		server:   grpc.NewServer(),
	}

	log.Infof("Listening on : \"%v\"\n", s.Addr())

	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)

	return s, nil
}

////////////////// util //////////////////////////

// Logs request instance properties
func logInstanceVars(r *authorization.HandleAuthorizationRequest) {
	props := decodeValueMap(r.Instance.Subject.Properties)
	log.Debugf("Instance request properties:")
	for key, val := range props {
		log.Debugf("key: %s\nvalue: \t%s", key, val)
	}
}

// Decodes gRPC values into string interface
func decodeValueMap(in map[string]*policy.Value) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = decodeValue(v.GetValue())
	}
	return out
}

// Decodes policy value into standard type
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

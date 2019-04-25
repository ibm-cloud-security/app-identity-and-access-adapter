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
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy"
	"istio.io/istio/mixer/adapter/ibmcloudappid/policy/manager"
	apistrategy "istio.io/istio/mixer/adapter/ibmcloudappid/strategy/api"
	//webstrategy "istio.io/istio/mixer/adapter/ibmcloudappid/strategy/web"
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

	// AppidAdapter supports authorization template.
	AppidAdapter struct {
		listener    net.Listener
		server      *grpc.Server
		apistrategy *apistrategy.APIStrategy
		manager     manager.PolicyManager
	}
)

var _ authorization.HandleAuthorizationServiceServer = &AppidAdapter{}

////////////////// adapter.Handler //////////////////////////

// HandleAuthorization evaulates authoroization policy using api/web strategy
func (s *AppidAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Debugf("HandleAuthorization :: received request\n")

	action := s.manager.Evaluate(r.Instance.Action)

	switch action.Type {
	case policy.API:
		return s.apistrategy.HandleAuthorizationRequest(r, action.Client)
	case policy.WEB:
		fallthrough
	default:
		return &v1beta1.CheckResult{Status: status.OK}, nil
	}
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
func NewAppIDAdapter(port uint16) (Server, error) {
	saddr := fmt.Sprintf(":%d", port)

	// Ensure we have correct configuration
	listener, err := net.Listen("tcp", saddr)
	if err != nil {
		log.Errorf("Unable to listen on socket: %v", err)
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}

	s := &AppidAdapter{
		listener:    listener,
		apistrategy: apistrategy.New(),
		server:      grpc.NewServer(),
		manager:     manager.New(),
	}

	log.Infof("Listening on : \"%v\"\n", s.Addr())

	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)

	return s, nil
}

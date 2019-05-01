// nolint:lll
// Generates the appidadpater's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/ibmcloudappid/adapter/config/config.proto -x "-s=false -n ibmcloudappid -t authorization"

package adapter

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/initializer"
	"ibmcloudappid/adapter/policy/manager"
	"ibmcloudappid/adapter/strategy"
	apistrategy "ibmcloudappid/adapter/strategy/api"
	"istio.io/api/mixer/adapter/model/v1beta1"
	//webstrategy "ibmcloudappid/adapter/strategy/web"
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
		apistrategy strategy.Strategy
		manager     manager.PolicyManager
	}
)

var _ authorization.HandleAuthorizationServiceServer = &AppidAdapter{}

////////////////// adapter.Handler //////////////////////////

// HandleAuthorization evaulates authoroization policy using api/web strategy
func (s *AppidAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Debugf("Handling authorization request : %v", r.Instance.Action)

	// Check policy
	actions := s.manager.Evaluate(r.Instance.Action)

	switch actions.Type {
	case policy.JWT:
		log.Info("Executing JWT policies")
		return s.apistrategy.HandleAuthorizationRequest(r, actions.Policies)
	case policy.OIDC:
		log.Info("OIDC policies are not supported")
		return &v1beta1.CheckResult{Status: status.OK}, nil
	default:
		log.Debug("No OIDC/JWT policies configured")
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
func NewAppIDAdapter(addr string) (Server, error) {

	// Being listening for requests
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("Unable to listen on socket: %v", err)
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}

	// Initialize Kubernetes
	p, err := initializer.New()
	if err != nil {
		log.Errorf("Unable to initialize adapter: %v", err)
		return nil, err
	}

	s := &AppidAdapter{
		listener:    listener,
		apistrategy: apistrategy.New(),
		server:      grpc.NewServer(),
		manager:     p.GetManager(),
	}

	log.Infof("Listening on : \"%v\"\n", s.Addr())

	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)

	return s, nil
}

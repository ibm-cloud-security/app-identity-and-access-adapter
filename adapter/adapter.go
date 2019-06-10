// nolint:lll
// Generates the appidadpater's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/config/config.proto -x "-s=false -n ibmcloudappid -t authorization"

package adapter

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/initializer"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/store"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/strategy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/strategy/api"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/strategy/web"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"istio.io/api/mixer/adapter/model/v1beta1"
	"istio.io/istio/mixer/pkg/status"
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
		webstrategy strategy.Strategy
		engine      engine.PolicyEngine
	}
)

////////////////// adapter.Handler //////////////////////////

// HandleAuthnZ evaluates authn/z policies using api/web strategy
func (s *AppidAdapter) HandleAuthnZ(ctx context.Context, r *authnz.HandleAuthnZRequest) (*authnz.HandleAuthnZResponse, error) {
	///// Validate input /////
	if err := validateAuthnzRequest(r); err != nil {
		zap.S().Errorf("Unexpected template format for HandleAuthnZRequest: %v", r)
		return nil, err
	}

	///// Check policy
	action, err := s.engine.Evaluate(r.Instance.Target)
	if err != nil {
		zap.L().Debug("Could not check policies", zap.Error(err))
		return nil, err
	}

	switch action.Type {
	case policy.JWT:
		zap.L().Info("Executing JWT policies")
		return s.apistrategy.HandleAuthnZRequest(r, action)
	case policy.OIDC:
		zap.L().Info("Executing OIDC policies")
		return s.webstrategy.HandleAuthnZRequest(r, action)
	default:
		zap.L().Info("No OIDC/JWT policies configured")
		return &authnz.HandleAuthnZResponse{
			Result: &v1beta1.CheckResult{Status: status.OK},
		}, nil
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

	// Begin listening for requests
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		zap.L().Fatal("Unable to listen on socket", zap.Error(err))
		return nil, err
	}

	localStore := store.New()

	// Initialize Kubernetes
	init, err := initializer.New(localStore)
	if err != nil {
		zap.L().Fatal("Unable to initialize adapter", zap.Error(err))
		return nil, err
	}

	eng, err := engine.New(localStore)
	if err != nil {
		zap.L().Fatal("Unable to initialize policy engine", zap.Error(err))
		return nil, err
	}

	s := &AppidAdapter{
		listener:    listener,
		apistrategy: apistrategy.New(),
		webstrategy: webstrategy.New(init.GetKubeClient()),
		server:      grpc.NewServer(),
		engine:      eng,
	}

	zap.S().Infof("Listening on: %v", s.Addr())

	authnz.RegisterHandleAuthnZServiceServer(s.server, s)

	return s, nil
}

////////////////// utils //////////////////////////

func validateAuthnzRequest(r *authnz.HandleAuthnZRequest) error {
	if r == nil || r.Instance == nil || r.Instance.Request == nil || r.Instance.Target == nil {
		zap.L().Error("Invalid instance format. Please check that the instance.yaml is sending telemetry according to the template.")
		return errors.New("invalid *authnz.HandleAuthnZRequest instance format")
	}
	if r.Instance.Request.Params == nil || r.Instance.Request.Headers == nil {
		zap.L().Error("Invalid instance format. Please check that the instance.yaml is sending telemetry according to the template.")
		return errors.New("invalid *authnz.HandleAuthnZRequest instance format")
	}
	// Trim trailing slash for any route except the root. Empty roots are already routed to "/".
	if r.Instance.Target.Path != "/" && strings.HasSuffix(r.Instance.Target.Path, "/") {
		r.Instance.Target.Path = strings.TrimRight(r.Instance.Target.Path, "/")
	}
	return nil
}

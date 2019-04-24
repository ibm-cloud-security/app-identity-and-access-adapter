// nolint:lll
// Generates the appidadpater's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/ibmcloudappid/config/config.proto -x "-s=false -n ibmcloudappid -t authorization"

package ibmcloudappid

import (
	"context"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc"
	"istio.io/api/mixer/adapter/model/v1beta1"
	adapter "istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	authpolicy "istio.io/istio/mixer/adapter/ibmcloudappid/policy"
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
	log.Infof("HandleAuthorization :: received request\n")

	logInstanceVars(r)

	// Get destination service
	props := decodeValueMap(r.Instance.Subject.Properties)
	destinationService := strings.TrimSuffix(props["destination_service_host"].(string), ".svc.cluster.local")

	// Get policy to enforce
	policies := s.manager.GetPolicies(destinationService)
	if policies == nil || len(policies) == 0 {
		log.Infof("HandleAuthorization ::no policies exists for service: %s\n", destinationService)
		return &adapter.CheckResult{Status: status.OK}, nil
	}
	policyToEnforce := policies[0]
	client := s.manager.GetClient(policyToEnforce.ClientName)

	// Enforce as API policy
	if policyToEnforce.Type == authpolicy.API {
		return s.apistrategy.HandleAuthorizationRequest(r, &client)
	}

	// Enforce WEB policy in the future
	return &adapter.CheckResult{Status: status.OK}, nil
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

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", "47304"))
	if err != nil {
		log.Errorf("Unable to listen on socket: %v", err)
		return nil, fmt.Errorf("Unable to listen on socket: %v", err)
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

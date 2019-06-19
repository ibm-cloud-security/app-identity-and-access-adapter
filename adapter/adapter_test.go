package adapter

// Disable tests until framework can read kubeconfig
import (
	"context"
	"errors"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/fake"
	"testing"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/config"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter/policy/engine"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/config/template"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/mixer/pkg/status"
)

func TestNew(t *testing.T) {
	server, err := NewAppIDAdapter(config.NewConfig())
	defer server.Close()
	assert.Nil(t, err)
	s := server.(*AppidAdapter)
	assert.NotNil(t, s.webstrategy)
	assert.NotNil(t, s.apistrategy)
	assert.NotNil(t, s.listener)
	assert.NotNil(t, s.engine)
	assert.NotNil(t, s.server)
}

func TestHandleAuthorization(t *testing.T) {
	server, err := NewAppIDAdapter(config.NewConfig())
	defer server.Close()
	assert.Nil(t, err)
	mock := &mockEngine{}

	s := server.(*AppidAdapter)
	s.engine = mock

	tests := []struct {
		req    *authnz.HandleAuthnZRequest
		status rpc.Status
		action *engine.Action
		err    error
	}{
		{
			req:    &authnz.HandleAuthnZRequest{},
			status: status.OK,
			action: &engine.Action{Type: policy.NONE},
			err:    errors.New("invalid *authnz.HandleAuthnZRequest instance format"),
		},
		{
			req: &authnz.HandleAuthnZRequest{
				Instance: &authnz.InstanceMsg{
					Request: &authnz.RequestMsg{},
					Target:  &authnz.TargetMsg{},
				},
			},
			status: status.OK,
			action: &engine.Action{Type: policy.NONE},
			err:    errors.New("invalid *authnz.HandleAuthnZRequest instance format"),
		},
		{
			req:    generateAuthRequest("", "/hello/"),
			status: status.OK,
			action: &engine.Action{Type: policy.NONE},
			err:    nil,
		},
		{
			req:    generateAuthRequest("bearer token1 token2", "/"),
			status: status.New(16),
			action: &engine.Action{Type: policy.JWT},
			err:    nil,
		},
		{
			req:    generateAuthRequest("", "/"),
			status: status.New(16),
			action: &engine.Action{
				Type:   policy.OIDC,
				Client: fake.NewClient(nil),
			},
			err: nil,
		},
		{
			req:    generateAuthRequest("", "/"),
			status: status.New(16),
			action: nil,
			err:    errors.New(""),
		},
	}

	for _, ts := range tests {
		test := ts
		t.Run("adapter", func(t *testing.T) {
			//t.Parallel()
			mock.action = test.action
			mock.err = test.err
			result, err := s.HandleAuthnZ(context.Background(), test.req)
			if test.err != nil {
				assert.EqualError(t, test.err, err.Error())
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.status.Code, result.Result.Status.Code)
			}
		})
	}
}

type mockEngine struct {
	action *engine.Action
	err    error
}

func (m *mockEngine) Evaluate(msg *authnz.TargetMsg) (*engine.Action, error) {
	return m.action, m.err
}

func generateAuthRequest(header string, path string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Request: &authnz.RequestMsg{
				Headers: &authnz.HeadersMsg{
					Authorization: header,
				},
				Params: &authnz.QueryParamsMsg{
					Error: "",
					Code:  "",
				},
			},
			Target: &authnz.TargetMsg{
				Path: path,
			},
		},
	}
}

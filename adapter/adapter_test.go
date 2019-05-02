package adapter

import (
	"context"
	"testing"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/stretchr/testify/assert"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/engine"
	"istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
)

func TestNew(t *testing.T) {
	server, err := NewAppIDAdapter("")
	defer server.Close()
	assert.Nil(t, err)
	s := server.(*AppidAdapter)
	assert.NotNil(t, s.apistrategy)
	assert.NotNil(t, s.listener)
	assert.NotNil(t, s.engine)
	assert.NotNil(t, s.server)
}

func TestHandleAuthorization(t *testing.T) {
	server, err := NewAppIDAdapter("")
	defer server.Close()
	assert.Nil(t, err)
	mock := &mockEngine{}

	s := server.(*AppidAdapter)
	s.engine = mock

	tests := []struct {
		req    *authorization.HandleAuthorizationRequest
		status rpc.Status
		action engine.Action
	}{
		{
			req:    generateAuthRequest(""),
			status: status.OK,
			action: engine.Action{Type: policy.NONE},
		},
		{
			req:    generateAuthRequest("bearer token1 token2"),
			status: status.OK,
			action: engine.Action{Type: policy.JWT},
		},
		{
			req:    generateAuthRequest(""),
			status: status.OK,
			action: engine.Action{Type: policy.OIDC}, // Not yet supported
		},
	}

	for _, test := range tests {
		mock.action = test.action
		result, err := s.HandleAuthorization(context.Background(), test.req)
		assert.Nil(t, err)
		assert.Equal(t, result.Status, test.status)
	}
}

type mockEngine struct {
	action engine.Action
}

func (m *mockEngine) Evaluate(*authorization.ActionMsg) engine.Action {
	return m.action
}

func generateAuthRequest(header string) *authorization.HandleAuthorizationRequest {
	return &authorization.HandleAuthorizationRequest{
		Instance: &authorization.InstanceMsg{
			Name: "",
			Subject: &authorization.SubjectMsg{
				Properties: map[string]*v1beta1.Value{
					"authorization_header": &v1beta1.Value{
						Value: &v1beta1.Value_StringValue{
							StringValue: header,
						},
					},
				},
			},
			Action: nil,
		},
	}
}

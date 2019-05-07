package adapter

import (
	"context"
	"errors"
	"testing"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/stretchr/testify/assert"
	"ibmcloudappid/adapter/policy"
	"ibmcloudappid/adapter/policy/engine"
	"ibmcloudappid/config/template"
	"istio.io/istio/mixer/pkg/status"
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
		req    *authnz.HandleAuthnZRequest
		status rpc.Status
		action *engine.Action
		err    error
	}{
		{
			req:    generateAuthRequest(""),
			status: status.OK,
			action: &engine.Action{Type: policy.NONE},
			err:    nil,
		},
		{
			req:    generateAuthRequest("bearer token1 token2"),
			status: status.OK,
			action: &engine.Action{Type: policy.JWT},
			err:    nil,
		},
		/*{
			req:    generateAuthRequest(""),
			status: status.OK,
			action: &engine.Action{Type: policy.OIDC}, // Not yet supported
			err:    nil,
		},*/
		{
			req:    generateAuthRequest(""),
			status: status.OK,
			action: nil,
			err:    errors.New(""),
		},
	}

	for _, test := range tests {
		mock.action = test.action
		mock.err = test.err
		result, err := s.HandleAuthnZ(context.Background(), test.req)
		if test.err != nil {
			assert.Equal(t, err, test.err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, result.Result.Status, test.status)
		}
	}
}

type mockEngine struct {
	action *engine.Action
	err    error
}

func (m *mockEngine) Evaluate(*authnz.ActionMsg) (*engine.Action, error) {
	return m.action, m.err
}

func generateAuthRequest(header string) *authnz.HandleAuthnZRequest {
	return &authnz.HandleAuthnZRequest{
		Instance: &authnz.InstanceMsg{
			Name: "",
			Subject: &authnz.SubjectMsg{
				Credentials: &authnz.CredentialsMsg{
					AuthorizationHeader: header,
				},
			},
			Action: nil,
		},
	}
}

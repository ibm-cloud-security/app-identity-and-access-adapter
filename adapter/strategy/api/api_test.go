package apistrategy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseRequest(t *testing.T) {
	var tests = []struct {
		props       map[string]interface{}
		expectErr   bool
		expectedMsg string
	}{
		{
			map[string]interface{}{"dummy": "value"},
			true,
			"authorization header not provided",
		},
		{
			map[string]interface{}{"authorization_header": ""},
			true,
			"authorization header not provided",
		},
		{
			map[string]interface{}{"authorization_header": "bearer"},
			true,
			"authorization header malformed - expected 'Bearer <access_token> <optional id_token>'",
		},
		{
			map[string]interface{}{"authorization_header": "b access id"},
			true,
			"unsupported authorization header format - expected 'Bearer <access_token> <optional id_token>'",
		},
		{
			map[string]interface{}{"authorization_header": "Bearer access id"},
			false,
			"",
		},
		{
			map[string]interface{}{"authorization_header": "bearer access id"},
			false,
			"",
		},
	}

	for _, e := range tests {
		tokens, err := getAuthTokensFromRequest(e.props)
		if !e.expectErr && tokens != nil {
			assert.Equal(t, "access", tokens.access)
			assert.Equal(t, "id", tokens.id)
		} else {
			assert.EqualError(t, err, e.expectedMsg)
		}

	}
}

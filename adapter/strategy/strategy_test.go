package strategy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"istio.io/api/policy/v1beta1"
)

func TestDecodeValueMap(t *testing.T) {
	m := generateMap()
	strInterfaceMap := DecodeValueMap(m)
	assert.Equal(t, "Value_StringValue", strInterfaceMap["Value_StringValue"])
	assert.Equal(t, int64(1), strInterfaceMap["Value_Int64Value"])
	assert.Equal(t, float64(10), strInterfaceMap["Value_DoubleValue"])
	assert.NotNil(t, strInterfaceMap["Value_IpAddressValue"])
	assert.Equal(t, "&Value_BoolValue{BoolValue:true,}", strInterfaceMap["Value_BoolValue"])

}

func generateMap() map[string]*v1beta1.Value {
	return map[string]*v1beta1.Value{
		"Value_BoolValue": &v1beta1.Value{
			Value: &v1beta1.Value_BoolValue{
				BoolValue: true,
			},
		},
		"Value_StringValue": &v1beta1.Value{
			Value: &v1beta1.Value_StringValue{
				StringValue: "Value_StringValue",
			},
		},
		"Value_Int64Value": &v1beta1.Value{
			Value: &v1beta1.Value_Int64Value{
				Int64Value: int64(1),
			},
		},
		"Value_DoubleValue": &v1beta1.Value{
			Value: &v1beta1.Value_DoubleValue{
				DoubleValue: 10,
			},
		},
		"Value_IpAddressValue": &v1beta1.Value{
			Value: &v1beta1.Value_IpAddressValue{
				IpAddressValue: &v1beta1.IPAddress{
					Value: make([]byte, 0),
				},
			},
		},
	}
}

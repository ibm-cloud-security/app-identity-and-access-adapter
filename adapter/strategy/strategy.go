package strategy

import (
	"fmt"
	"ibmcloudappid/adapter/policy/engine"
	"ibmcloudappid/config/template"
	policy "istio.io/api/policy/v1beta1"
)

// Strategy defines the entry point to an authentication handler
type Strategy interface {
	HandleAuthnZRequest(*authnz.HandleAuthnZRequest, []engine.PolicyAction) (*authnz.HandleAuthnZResponse, error)
}

// DecodeValueMap decodes gRPC values into string interface
func DecodeValueMap(in map[string]*policy.Value) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = decodeValue(v.GetValue())
	}
	return out
}

// DecodeValue decodes policy value into standard type
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

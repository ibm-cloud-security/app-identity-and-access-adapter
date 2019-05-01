package strategy

import (
	"fmt"
	"ibmcloudappid/adapter/policy/handler"
	"istio.io/api/mixer/adapter/model/v1beta1"
	policy "istio.io/api/policy/v1beta1"
	"istio.io/istio/mixer/template/authorization"
)

// Strategy defines the entry point to an authentication handler
type Strategy interface {
	HandleAuthorizationRequest(*authorization.HandleAuthorizationRequest, []handler.PolicyAction) (*v1beta1.CheckResult, error)
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

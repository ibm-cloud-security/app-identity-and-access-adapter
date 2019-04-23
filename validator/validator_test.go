package validator

import (
	"github.com/dgrijalva/jwt-go"
	"istio.io/istio/mixer/adapter/ibmcloudappid/client"
	"testing"
)

const (
	testKid          = "appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497"
	testValidToken   = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwcElkLTcxYjM0ODkwLWE5NGYtNGVmMi1hNGI2LWNlMDk0YWE2ODA5Mi0yMDE4LTA4LTAyVDExOjUzOjM2LjQ5NyIsInZlcnNpb24iOjR9.eyJpc3MiOiJodHRwczovL2V1LWdiLmFwcGlkLnRlc3QuY2xvdWQuaWJtLmNvbS9vYXV0aC92NC83MWIzNDg5MC1hOTRmLTRlZjItYTRiNi1jZTA5NGFhNjgwOTIiLCJleHAiOjE1NTA4NzMwNzQsImF1ZCI6WyIzYjljNDE0ZTIzYjU3ZWY1Y2I3NDFjMGQ3ZjZkNzM3MmQyMTI2NzYzIl0sImF6cCI6IjNiOWM0MTRlMjNiNTdlZjVjYjc0MWMwZDdmNmQ3MzcyZDIxMjY3NjMiLCJzdWIiOiJmNGJiNzczMy02ZTRlLTRhNTMtOWE0YS04YzVkMmNlZTA2ZWEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYW1yIjpbImNsb3VkX2RpcmVjdG9yeSJdLCJpYXQiOjE1NTA4Njk0NzQsInRlbmFudCI6IjcxYjM0ODkwLWE5NGYtNGVmMi1hNGI2LWNlMDk0YWE2ODA5MiIsInNjb3BlIjoib3BlbmlkIGFwcGlkX2RlZmF1bHQgYXBwaWRfcmVhZHByb2ZpbGUgYXBwaWRfcmVhZHVzZXJhdHRyIGFwcGlkX3dyaXRldXNlcmF0dHIgYXBwaWRfYXV0aGVudGljYXRlZCJ9.Yg_13wauGdw13jtLNyG0KZqQhHJvRvCZB4aRvsCE7vyLmTS1qb4Yz7UasxvMdNOPvtk74KFVtg-gup2ptbCpJB7sH6QgQAWxp4eNVRbjAPgP-q1gZ-_5P-uxU2Sr5YwiMUin_bnIRImqaoRayqbkRV30BbB9enAt-VIONDAO002d8yOLr5ReWPcFCCfPLnVnIne2gv3-S8grbTHV7AwQ7TYrQbmC9VgAy678qttIg7shGxSKWyNAlybzPl7wN6YlXclilog5yhhDL9gGemDlez_SAQyyDi1dFpoNuv_xQRBfdXaLpmB9bFQ-zCx2xlDWHiPv5AON8stDwEXkwsfBaA"
	testExpiredToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UifQ.eyJpc3MiOiJpbWYtYXV0aHNlcnZlci5zdGFnZTEubXlibHVlbWl4Lm5ldCIsImV4cCI6MTQ4OTk1NzQ1OSwiYXVkIjoiNDA4ZWIzNmEyYTA2OWFkODljZDE5Yzc4OWE5NmI3Y2YzNmI1NTBlYyIsInN1YiI6IjA5YjdmZWE1LTJlNGUtNDBiOC05ZDgxLWRmNTAwNzFhMzA1MyIsImFtciI6WyJmYWNlYm9vayJdLCJpYXQiOjE0ODczNjU0NTksInRlbmFudCI6IjUwZDBiZWVkLWFkZDctNDhkZC04YjBhLWM4MThjYjQ1NmJiNCIsInNjb3BlIjoiYXBwaWRfZGVmYXVsdCBhcHBpZF9yZWFkcHJvZmlsZSBhcHBpZF9yZWFkdXNlcmF0dHIgYXBwaWRfd3JpdGV1c2VyYXR0ciJ9.gQq4_IxbkPg1FsVZiiTqsejURL4E_Ijr8U1vDob-06GcsorVijS7HHf0kgWD84cDNa6z4Lp7HkmvI8vmiUIfV6ch-xJS_LSJphKy5nZxXqVHchRDJAMUNMiAYqC5ohZ4MXmjuGFIrVl1iZdTyP5Oz-5e6UzDccdAGkPokNs_IyXwiSmGWF5fOKSgfqANYwRBaC-JeXlzEcVZ697q92kiErBNl3ziuSFWxss86ZHHiKdLoHUpkDRKgPHwSQmE_Kwzj8v8Td9WuIVwXCF-D4koTuPJSe2aPqCLuV28PE9wRh5j3sFraKbQIcjuHuiAd5KBhzwaeVT20_0zrgyr3QG0Vg"
)

var testClient = client.Client{}

/////// Token Validation ///////
/*
func TestValidToken(t *testing.T) {
	v := New()
	err := v.Validate(testClient, testValidToken)
	if err != nil {
		t.Errorf("Expected to validate token : err %s", err)
	}
}

func TestInvalidTokenSig(t *testing.T) {
	v := New()
	err := v.Validate(testClient, testValidToken)
	if err != nil {
		t.Errorf("Expected to validate token : err %s", err)
	}
}

func TestInvalidTokenTenant(t *testing.T) {
	v := New()
	err := v.Validate(testClient, testValidToken)
	if err != nil {
		t.Errorf("Expected to validate token : err %s", err)
	}
}

func TestInvalidTokenExpired(t *testing.T) {
	v := New()
	err := v.Validate(testClient, testExpiredToken)
	if err == nil || err.Error() != "expired" {
		t.Errorf("Expected to fail token validation for expiry : err %s", err)
	}
}
*/
/////// Claim Validation //////

func TestClaimValidation(t *testing.T) {
	var claimMap jwt.MapClaims = make(map[string]interface{})
	claimMap["tenant"] = "1234"
	err := validateClaim("tenant", "1234", claimMap)
	if err != nil {
		t.Errorf("Expected to fail token validation for expiry : err %s", err)
	}

	err = validateClaim("tenant2", "1234", claimMap)
	if err == nil || err.Error() != "token validation error - expected claim `tenant2` to exist" {
		t.Errorf("Expected to fail token validation for expiry : err %s", err)
	}
}

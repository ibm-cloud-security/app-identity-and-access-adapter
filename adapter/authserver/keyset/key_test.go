package keyset

import (
	"testing"
)

const (
	rsaKTY = "RSA"
	rsaN   = "ALePj2tZTsUDtGlBKMPU1GjbdpVdKPITqDyLM4YhktHzrB2tt690Sdkr5g8wTFflhMEsNARxQnDr7ZywIgsCvpAqv8JSzuoIu-N8hp3FJeGvMJ_4Fh7mlrxh_KVE7Xv1zbqCGSrmsiWsA-Y0Fxt4QEcPlPd_BDh1W7_vm5WuP0sCNsclziq9t7UIrIrvHXFRA9nuxMsM2OfaisU0T9PczfO16EuJW6jflmP6J3ewoJ1AT1SbX7e98ecyD2Ke5I0ta33yk7AVCLtzubJz2NCDGPTWRivqFC0J1OkV90jzme4Eo7zs-CDK-ItVCkV4mgX6Caknd_j2hucGN4fMUDviWwE"
	rsaE   = "AQAB"
)

/////// Public key decoding happy flows //////
func TestDecodeRSAPublicKey(t *testing.T) {
	k := &key{Kty: rsaKTY, N: rsaN, E: rsaE}
	key, err := k.decodePublicKey()
	if err != nil {
		t.Errorf("Could not decode public key : %s", err)
	}
	if key == nil {
		t.Errorf("Expected public key to be returned")
	}
}

/////// Public key decoding unhappy flows //////

func TestDecodeUnknownPublicKeyType(t *testing.T) {
	k := &key{
		Kty: "other",
	}
	_, err := k.decodePublicKey()
	if err == nil || err.Error() != "unknown JWK key type other" {
		t.Errorf("Expected unknown public key type : %s", err)
	}
}

func TestDecodeRSAMissingFields(t *testing.T) {
	k := &key{Kty: rsaKTY, N: "", E: "a"}
	_, err := k.decodePublicKey()
	if err == nil || err.Error() != "malformed JWK RSA key" {
		t.Errorf("Expected to receive malformed JWK error : %s", err)
	}

	k.E = ""
	k.N = "something"
	_, err = k.decodePublicKey()
	if err == nil || err.Error() != "malformed JWK RSA key" {
		t.Errorf("Expected to receive malformed JWK error : %s", err)
	}
}

func TestDecodeRSAInvalidN(t *testing.T) {
	k := &key{Kty: rsaKTY, N: "!", E: rsaE}
	_, err := k.decodePublicKey()
	if err == nil || err.Error() != "malformed JWK RSA key modulus" {
		t.Errorf("Expected to receive malformed JWK error : %s", err)
	}
}

func TestDecodeRSAInvalidE(t *testing.T) {
	k := &key{Kty: rsaKTY, N: rsaN, E: "?"}
	_, err := k.decodePublicKey()
	if err == nil || err.Error() != "malformed JWK RSA key exponent" {
		t.Errorf("Expected to receive malformed JWK error : %s", err)
	}
}

/////// Public key safe decoding //////

func TestSafeDecodeURLEncoded(t *testing.T) {
	bytes, err := safeDecode(rsaN)
	if err != nil {
		t.Errorf("Could not decode URL encoded public key : %s", err)
	}
	if len(bytes) != 257 {
		t.Errorf("Improperly decoded key : %d", len(bytes))
	}
}

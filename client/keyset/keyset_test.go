package keyset

import (
	"github.com/stretchr/testify/assert"
	utils "istio.io/istio/mixer/adapter/ibmcloudappid/testing"
	"net/http"
	"testing"
)

const (
	testURL                            = "http://localhost:6002/publicKeys"
	testKid                            = "appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497"
	publicKeysOkResponse               = "{\r\n  \"keys\": [\r\n    {\r\n      \"kty\": \"RSA\",\r\n      \"use\": \"sig\",\r\n      \"n\": \"AMniJfma7obdg2AMkucEo5QV4ohy6rHPnuYl7gOGTKLdkQ2cpPx4a5viHaKiny3KpqfR2ny7OvsmB3UAYk3_rfCaNrtB5_zz2H-GxxDPYEPniYztU9aRyw5NlWUtpcAAkaXPRkzfKndUFg74W8h_HHm0DL-5KySiAPcfNnyT6fvf0ycNtYbngh0CSNzJQq7vZDZboZMaVkASgR11uOGV-RGnQ4shRc4z3qv7f4_jnDW4WsB0RzrgPGRJ9fSNrQS78LAfIbdzigfgR4_TxifhemwzYwpJ5PYV2pxHs6DuLUODbvIhWahZR_iJWoxpZZdxNDirycJ2CP_On1T3-urz4SM\",\r\n      \"e\": \"AQAB\",\r\n      \"kid\": \"appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497\"\r\n    }\r\n  ]\r\n}"
	publicKeysInvalidKeyFormatResponse = "{\r\n  \"keys\": [\r\n    {\r\n      \"kty\": \"RSA\",\r\n      \"use\": \"sig\",\r\n      \"n\": \"!\",\r\n      \"e\": \"!\",\r\n      \"kid\": \"appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497\"\r\n    }\r\n  ]\r\n}"
	publicKeysMissingKid               = "{\r\n  \"keys\": [\r\n    {\r\n      \"kty\": \"RSA\",\r\n      \"use\": \"sig\",\r\n      \"n\": \"AMniJfma7obdg2AMkucEo5QV4ohy6rHPnuYl7gOGTKLdkQ2cpPx4a5viHaKiny3KpqfR2ny7OvsmB3UAYk3_rfCaNrtB5_zz2H-GxxDPYEPniYztU9aRyw5NlWUtpcAAkaXPRkzfKndUFg74W8h_HHm0DL-5KySiAPcfNnyT6fvf0ycNtYbngh0CSNzJQq7vZDZboZMaVkASgR11uOGV-RGnQ4shRc4z3qv7f4_jnDW4WsB0RzrgPGRJ9fSNrQS78LAfIbdzigfgR4_TxifhemwzYwpJ5PYV2pxHs6DuLUODbvIhWahZR_iJWoxpZZdxNDirycJ2CP_On1T3-urz4SM\",\r\n      \"e\": \"AQAB\" }\r\n  ]\r\n}"
	badReqResponse                     = "{\"error\":\"invalid tenant\"}"
)

func TestNew(t *testing.T) {
	var tests = []struct {
		name   string
		res    string
		length int
	}{
		{"success", publicKeysOkResponse, 1},
		{"failure", publicKeysMissingKid, 0},
	}

	for _, e := range tests {

		h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.URL.String(), "/publicKeys")
			assert.Equal(t, req.Header.Get("xFilterType"), "IstioAdapter")
			w.Write([]byte(e.res))
		})

		// Start a local HTTP server
		_, server := utils.HTTPClient(h)

		// Server URL
		url := server.URL + "/publicKeys"

		// Test
		util := New(url).(*RemoteKeySet)
		if util == nil {
			t.Errorf("Could not convert KeySet interface to RemoteKeySet")
			return
		}
		assert.Equal(t, util.publicKeyURL, url)
		assert.Equal(t, len(util.publicKeys), e.length)

		// close server
		server.Close()
	}
}

func TestRetrievePublicKeys(t *testing.T) {
	var tests = []struct {
		name          string
		res           string
		status        int
		shouldSucceed bool
		length        int
	}{
		{"success", publicKeysOkResponse, http.StatusOK, true, 1},
		{"missing kid", publicKeysMissingKid, http.StatusOK, true, 0},
		{"invalid key format", publicKeysInvalidKeyFormatResponse, http.StatusOK, true, 0},
		{"bad request", badReqResponse, http.StatusBadRequest, false, 0},
		{"invalid payload", "", http.StatusOK, false, 0},
	}

	for _, e := range tests {
		// Overrite Http req handler
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(e.status)
			w.Write([]byte(e.res))
		})
		httpClient, server := utils.HTTPClient(h)

		// Generate new key util
		util := New(testURL).(*RemoteKeySet)
		util.httpClient = httpClient

		if e.shouldSucceed {
			assert.Equal(t, util.RetrievePublicKeys(), nil)
		} else {
			assert.NotEqual(t, util.RetrievePublicKeys(), nil)
		}
		assert.Equal(t, len(util.PublicKeys()), e.length)
		if e.length == 1 {
			assert.NotNil(t, util.PublicKey(testKid))
		}

		// cleanup
		server.Close()
	}
}

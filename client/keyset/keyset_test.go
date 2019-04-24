package keyset

import (
	"github.com/stretchr/testify/assert"
	utils "istio.io/istio/mixer/adapter/ibmcloudappid/testing"
	"net/http"
	"testing"
)

const (
	testURL                            = "http://localhost:6002/publicKeys"
	testKid                            = "appId-bd9fb8c8-e8d7-4671-a7bb-48e2ed5fcb77-2019-01-23T22:42:34.284"
	publicKeysOkResponse               = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"n\":\"AJvyFiaRrL1IiQyV8Uy-xjmvvjB7Zsaz3VqeUhFMuvRNudKx5F4o8Etd3xYHCd_aGuOR2GbDSGcoVsXrc00rs-vpj1IWhP5QTofParfRScZsi4i0tyihD6uzaHGe9Bc3__iGwzZFSFTVadCxsmEwJ176ExfYHptY1Dv3TCmVZ-6LE0KghhY2PnaR9zua88TToOES7w2UN2EhMm3490eFV3llnKG02dX5x0QSBuP_7PITMHUTxy1MCmqso4KhwwD_qrCUuepcKc1u9S2DWPV6-gqApvKHn8DTqrdNXqbIyfNTGy3SVo1JFeJpWwLH31IKmZHWQ6A4tdyoHK7GrtcokfM\",\"e\":\"AQAB\",\"kid\":\"appId-bd9fb8c8-e8d7-4671-a7bb-48e2ed5fcb77-2019-01-23T22:42:34.284\"}]}"
	publicKeysInvalidKeyFormatResponse = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"n\":\"AJvyFiaRrL1IiQyV8Uy-xjmvvjB7Zsaz3VqeUhFMuvRNudKx5F4o8Etd3xYHCd_aGuOR2GbDSGcoVsXrc00rs-vpj1IWhP5QTofParfRScZsi4i0tyihD6uzaHGe9Bc3__iGwzZFSFTVadCxsmEwJ176ExfYHptY1Dv3TCmVZ-6LE0KghhY2PnaR9zua88TToOES7w2UN2EhMm3490eFV3llnKG02dX5x0QSBuP_7PITMHUTxy1MCmqso4KhwwD_qrCUuepcKc1u9S2DWPV6-gqApvKHn8DTqrdNXqbIyfNTGy3SVo1JFeJpWwLH31IKmZHWQ6A4tdyoHK7GrtcokfM\",\"e\":\"!\",\"kid\":\"appId-bd9fb8c8-e8d7-4671-a7bb-48e2ed5fcb77-2019-01-23T22:42:34.284\"}]}"
	publicKeysMissingKid               = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"n\":\"AJvyFiaRrL1IiQyV8Uy-xjmvvjB7Zsaz3VqeUhFMuvRNudKx5F4o8Etd3xYHCd_aGuOR2GbDSGcoVsXrc00rs-vpj1IWhP5QTofParfRScZsi4i0tyihD6uzaHGe9Bc3__iGwzZFSFTVadCxsmEwJ176ExfYHptY1Dv3TCmVZ-6LE0KghhY2PnaR9zua88TToOES7w2UN2EhMm3490eFV3llnKG02dX5x0QSBuP_7PITMHUTxy1MCmqso4KhwwD_qrCUuepcKc1u9S2DWPV6-gqApvKHn8DTqrdNXqbIyfNTGy3SVo1JFeJpWwLH31IKmZHWQ6A4tdyoHK7GrtcokfM\",\"e\":\"AQAB\"}]}"
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

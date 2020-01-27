package keyset

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/networking"

	"github.com/stretchr/testify/assert"
)

const (
	testURL                            = "http://localhost:6002/publicKeys"
	testKid                            = "appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497"
	publicKeysOkResponse               = "{\r\n  \"keys\": [\r\n    {\r\n      \"kty\": \"RSA\",\r\n      \"use\": \"sig\",\r\n      \"n\": \"AMniJfma7obdg2AMkucEo5QV4ohy6rHPnuYl7gOGTKLdkQ2cpPx4a5viHaKiny3KpqfR2ny7OvsmB3UAYk3_rfCaNrtB5_zz2H-GxxDPYEPniYztU9aRyw5NlWUtpcAAkaXPRkzfKndUFg74W8h_HHm0DL-5KySiAPcfNnyT6fvf0ycNtYbngh0CSNzJQq7vZDZboZMaVkASgR11uOGV-RGnQ4shRc4z3qv7f4_jnDW4WsB0RzrgPGRJ9fSNrQS78LAfIbdzigfgR4_TxifhemwzYwpJ5PYV2pxHs6DuLUODbvIhWahZR_iJWoxpZZdxNDirycJ2CP_On1T3-urz4SM\",\r\n      \"e\": \"AQAB\",\r\n      \"kid\": \"appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497\"\r\n    }\r\n  ]\r\n}"
	publicKeysWrongKeyResponse         = "{\r\n  \"keyss\": [\r\n    {\r\n      \"kty\": \"RSA\",\r\n      \"use\": \"sig\",\r\n      \"n\": \"AMniJfma7obdg2AMkucEo5QV4ohy6rHPnuYl7gOGTKLdkQ2cpPx4a5viHaKiny3KpqfR2ny7OvsmB3UAYk3_rfCaNrtB5_zz2H-GxxDPYEPniYztU9aRyw5NlWUtpcAAkaXPRkzfKndUFg74W8h_HHm0DL-5KySiAPcfNnyT6fvf0ycNtYbngh0CSNzJQq7vZDZboZMaVkASgR11uOGV-RGnQ4shRc4z3qv7f4_jnDW4WsB0RzrgPGRJ9fSNrQS78LAfIbdzigfgR4_TxifhemwzYwpJ5PYV2pxHs6DuLUODbvIhWahZR_iJWoxpZZdxNDirycJ2CP_On1T3-urz4SM\",\r\n      \"e\": \"AQAB\",\r\n      \"kid\": \"appId-71b34890-a94f-4ef2-a4b6-ce094aa68092-2018-08-02T11:53:36.497\"\r\n    }\r\n  ]\r\n}"
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
		{"failure", publicKeysWrongKeyResponse, 0},
	}

	for _, e := range tests {

		h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.URL.String(), "/publicKeys")
			assert.Equal(t, req.Header.Get("x-filter-type"), "IstioAdapter")
			w.Write([]byte(e.res))
		})

		// Start a local HTTP server
		_, server := httpClient(h)

		// Server URL
		url := server.URL + "/publicKeys"

		// Test
		util := New(url, networking.New()).(*RemoteKeySet)
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
func TestResyncMissingKeys(t *testing.T) {
	// Overwrite Http req handler
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(publicKeysOkResponse))
	})
	httpClient, server := httpClient(h)

	// Generate new key util
	util := &RemoteKeySet{
		publicKeyURL: testURL,
		httpClient:   httpClient,
	}

	assert.NotNil(t, util.PublicKey(testKid))
	// cleanup
	server.Close()
}

func TestUpdateKeys(t *testing.T) {
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

	for _, ts := range tests {
		test := ts
		t.Run(test.name, func(st *testing.T) {
			st.Parallel()
			// Overwrite Http req handler
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				w.Write([]byte(test.res))
			})
			httpClient, server := httpClient(h)

			// Generate new key util
			util := New(testURL, httpClient).(*RemoteKeySet)
			assert.Equal(st, util.PublicKeyURL(), testURL)
			_, err := util.updateKeys()
			if test.shouldSucceed {
				assert.Equal(st, err, nil)
			} else {
				assert.NotEqual(st, err, nil)
			}
			assert.Equal(st, len(util.publicKeys), test.length)
			if test.length == 1 {
				assert.NotNil(st, util.PublicKey(testKid))
			}

			// cleanup
			server.Close()
		})
	}
}

func TestUpdateKeysGrouped(t *testing.T) {
	var count = 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		time.Sleep(1000)
		w.Write([]byte(publicKeysOkResponse))
	})
	httpClient, server := httpClient(h)
	util := New(server.URL, httpClient).(*RemoteKeySet)
	assert.Equal(t, 1, count)
	count = 0
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			err := util.updateKeysGrouped()
			assert.Nil(t, err)
			wg.Done()
		}()
	}
	wg.Wait()
	if !(count >= 1 && count < 100) {
		assert.Fail(t, "Expected count to be less than 100")
	}

	server.Close()
}

// httpClient mock
func httpClient(handler http.Handler) (*networking.HTTPClient, *httptest.Server) {
	s := httptest.NewServer(handler)

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, s.Listener.Addr().String())
			},
		},
	}

	n := &networking.HTTPClient{
		Client: cli,
	}
	return n, s
}

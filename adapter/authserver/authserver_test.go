package authserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthServerNew(t *testing.T) {

	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte("{}"))
	})

	// Start a local HTTP server
	s := httptest.NewServer(h)
	defer s.Close()

	server := New(s.URL)
	assert.NotNil(t, server)
	remoteServer := server.(*RemoteServer)
	assert.NotNil(t, remoteServer.httpclient)
	assert.NotNil(t, remoteServer.keyset)
	assert.Equal(t, server.KeySet().PublicKeyURL(), s.URL)
}

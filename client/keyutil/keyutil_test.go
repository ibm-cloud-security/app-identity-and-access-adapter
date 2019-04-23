package keyutil

import (
	"testing"
)

const (
	testURL = "http://localhost:6002/publicKeys"
)

func TestNew(t *testing.T) {
	util := New(testURL).(*Util)
	if util == nil {
		t.Errorf("Could not convert KeyUtil interface to Util")
		return
	}
	if util.publicKeyURL != testURL {
		t.Errorf("Util publicKey URL not initialized correctly")
		return
	}
	if len(util.publicKeys) > 0 {
		t.Errorf("Public keys could not be retrieved on initialization")
		return
	}
}

func TestRetrieveKeysSuccess(t *testing.T) {
}

func TestRetrieveNetworkError(t *testing.T) {
}

func TestRetrieveKeysInvalidRequest(t *testing.T) {
}

func TestPublicKeys(t *testing.T) {
}

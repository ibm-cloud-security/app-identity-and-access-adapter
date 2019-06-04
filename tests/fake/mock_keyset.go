package fake

import "crypto"

type MockKeySet struct{}

func (m *MockKeySet) PublicKeyURL() string                  { return "" }
func (m *MockKeySet) PublicKey(kid string) crypto.PublicKey { return nil }

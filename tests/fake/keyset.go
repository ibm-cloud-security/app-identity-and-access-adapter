package fake

import "crypto"

type KeySet struct {
	url string
}

func (k *KeySet) PublicKeyURL() string                  { return k.url }
func (k *KeySet) PublicKey(kid string) crypto.PublicKey { return nil }

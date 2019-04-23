package keyutil

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
// structure that represents a cryptographic key (see RFC 7517).
type key struct {
	// The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC".
	Kty string `json:"kty"`

	// The "use" (public key use) parameter identifies the intended use of
	// the public key.  The "use" parameter is employed to indicate whether
	// a public key is used for encrypting data or verifying the signature
	// on data.
	Use string `json:"use,omitempty"`

	// The "kid" (key ID) parameter is used to match a specific key.  This
	// is used, for instance, to choose among a set of keys within a JWK Set
	// during key rollover.
	Kid string `json:"kid,omitempty"`

	// The "alg" (algorithm) parameter identifies the algorithm intended for
	// use with the key.
	Alg string `json:"alg,omitempty"`

	Crv string `json:"crv,omitempty"` // EC Curve
	X   string `json:"x,omitempty"`   // EC x coordinate
	Y   string `json:"y,omitempty"`   // EC y coordinate
	D   string `json:"d,omitempty"`   // RSA private exponent
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA public exponent
	K   string `json:"k,omitempty"`   // oct key
}

// A JSON Web Key Set (JWK Set) is a JavaScript Object Notation (JSON) data
// structure that represents a set of cryptographic key (see RFC 7517).
type keySet struct {
	// The 'keys' attribute is mandatory
	Keys []key `json:"keys"`
	// optional attributes may also be present but are currently ignored
}

// Decode as a public key
func (k *key) decodePublicKey() (crypto.PublicKey, error) {
	// The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC".  "kty" values should
	// either be registered in the IANA "JSON Web Key Types" registry
	// established by [JWA] or be a value that contains a Collision-
	// Resistant Name. The "kty" value is a case-sensitive string.
	switch k.Kty {
	case "RSA":
		if k.N == "" || k.E == "" {
			return nil, errors.New("malformed JWK RSA key")
		}

		// decode exponent
		data, err := safeDecode(k.E)
		if err != nil {
			return nil, errors.New("malformed JWK RSA key exponent")
		}
		if len(data) < 4 {
			ndata := make([]byte, 4)
			copy(ndata[4-len(data):], data)
			data = ndata
		}

		pubKey := &rsa.PublicKey{
			N: &big.Int{},
			E: int(binary.BigEndian.Uint32(data[:])),
		}

		data, err = safeDecode(k.N)
		if err != nil {
			return nil, errors.New("malformed JWK RSA key modulus")
		}
		pubKey.N.SetBytes(data)

		return pubKey, nil
	default:
		return nil, fmt.Errorf("unknown JWK key type %s", k.Kty)
	}
}

func safeDecode(str string) ([]byte, error) {
	lenMod4 := len(str) % 4
	if lenMod4 > 0 {
		str = str + strings.Repeat("=", 4-lenMod4)
	}

	integer, err := base64.URLEncoding.DecodeString(str) // RFC 7517 compliant encoding
	if err != nil {                                      // compensate for APPID and IAM services use base64 instead of base64url
		return base64.StdEncoding.DecodeString(str)
	}
	return integer, err

}

package es256

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"

	"github.com/ucarion/jwt"
	"github.com/ucarion/jwt/internal/verify"
)

const Algorithm = "ES256"

func Validate(pub *ecdsa.PublicKey, s []byte, v interface{}) error {
	claims, err := verify.Verify(Algorithm, s, func(data, sig []byte) error {
		if len(sig) != 64 {
			return jwt.ErrInvalidSignature
		}

		var sigR, sigS big.Int
		sigR.SetBytes(sig[0:32])
		sigS.SetBytes(sig[32:])

		h := sha256.New()
		h.Write(data)

		if !ecdsa.Verify(pub, h.Sum(nil), &sigR, &sigS) {
			return jwt.ErrInvalidSignature
		}

		return nil
	})

	if err != nil {
		return err
	}

	return json.Unmarshal(claims, v)
}

func Encode(priv *ecdsa.PrivateKey, v interface{}) ([]byte, error) {
	return verify.Encode(Algorithm, v, func(data []byte) ([]byte, error) {
		h := crypto.SHA256.New()
		h.Write(data)

		sigR, sigS, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
		if err != nil {
			return nil, err
		}

		sig := make([]byte, 64)
		copy(sig, sigR.Bytes())
		copy(sig[32:], sigS.Bytes())

		return sig, nil
	})
}

package rs256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"

	"github.com/ucarion/jwt"
	"github.com/ucarion/jwt/internal/verify"
)

const Algorithm = "RS256"

func Validate(pub *rsa.PublicKey, s []byte, v interface{}) error {
	claims, err := verify.Verify(Algorithm, s, func(data, sig []byte) error {
		h := sha256.New()
		h.Write(data)

		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), sig) != nil {
			return jwt.ErrInvalidSignature
		}

		return nil
	})

	if err != nil {
		return err
	}

	return json.Unmarshal(claims, v)
}

func Encode(priv *rsa.PrivateKey, v interface{}) ([]byte, error) {
	return verify.Encode(Algorithm, 256, v, func(data []byte) ([]byte, error) {
		h := crypto.SHA256.New()
		h.Write(data)

		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h.Sum(nil))
	})
}

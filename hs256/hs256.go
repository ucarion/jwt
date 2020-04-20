package hs256

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"

	"github.com/ucarion/jwt"
	"github.com/ucarion/jwt/internal/verify"
)

const Algorithm = "HS256"

func Validate(secret, s []byte, v interface{}) error {
	claims, err := verify.Verify(Algorithm, s, func(data, sig []byte) error {
		h := hmac.New(sha256.New, secret)
		h.Write(data)

		if !hmac.Equal(h.Sum(nil), sig) {
			return jwt.ErrInvalidSignature
		}

		return nil
	})

	if err != nil {
		return err
	}

	return json.Unmarshal(claims, v)
}

func Encode(secret []byte, v interface{}) ([]byte, error) {
	return verify.Encode(Algorithm, sha256.Size, v, func(data []byte) ([]byte, error) {
		h := hmac.New(sha256.New, secret)
		h.Write(data)

		return h.Sum(nil), nil
	})
}

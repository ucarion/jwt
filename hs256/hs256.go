package hs256

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/ucarion/jwt"
	"github.com/ucarion/jwt/internal/parts"
)

const Algorithm = "HS256"

func Validate(secret, s []byte, v interface{}) error {
	parts, err := parts.Parse(s)
	if err != nil {
		return err
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(parts.Header)
	if err != nil {
		return err
	}

	var header jwt.Header
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return err
	}

	if header.Algorithm != Algorithm {
		return jwt.ErrWrongAlgorithm
	}

	decodedSignature, err := base64.RawURLEncoding.DecodeString(parts.Signature)
	if err != nil {
		return err
	}

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(parts.Header + "." + parts.Claims))

	if !hmac.Equal(h.Sum(nil), decodedSignature) {
		return jwt.ErrInvalidSignature
	}

	decodedClaims, err := base64.RawURLEncoding.DecodeString(parts.Claims)
	if err != nil {
		return err
	}

	return json.Unmarshal(decodedClaims, v)
}

func Encode(secret []byte, v interface{}) ([]byte, error) {
	header := jwt.Header{Type: jwt.HeaderTypeJWT, Algorithm: Algorithm}
	encodedHeader, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	encodedClaims, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	payload := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + base64.RawURLEncoding.EncodeToString(encodedClaims)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(payload))

	return []byte(payload + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))), nil
}

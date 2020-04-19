package es256

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/ucarion/jwt"
	"github.com/ucarion/jwt/internal/parts"
)

const Algorithm = "ES256"

func Validate(pub *ecdsa.PublicKey, s []byte, v interface{}) error {
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

	if len(decodedSignature) != 64 {
		return jwt.ErrInvalidSignature
	}

	var sigR, sigS big.Int
	sigR.SetBytes(decodedSignature[0:32])
	sigS.SetBytes(decodedSignature[32:])

	h := sha256.New()
	h.Write([]byte(parts.Header + "." + parts.Claims))

	if !ecdsa.Verify(pub, h.Sum(nil), &sigR, &sigS) {
		return jwt.ErrInvalidSignature
	}

	decodedClaims, err := base64.RawURLEncoding.DecodeString(parts.Claims)
	if err != nil {
		return err
	}

	return json.Unmarshal(decodedClaims, v)
}

func Encode(priv *ecdsa.PrivateKey, v interface{}) ([]byte, error) {
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
	h := crypto.SHA256.New()
	h.Write([]byte(payload))

	sigR, sigS, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 64)
	copy(signature, sigR.Bytes())
	copy(signature[32:], sigS.Bytes())

	return []byte(payload + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}

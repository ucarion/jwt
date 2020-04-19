package rs256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/ucarion/jwt"
	"github.com/ucarion/jwt/internal/parts"
)

const Algorithm = "RS256"

func Validate(pub *rsa.PublicKey, s []byte, v interface{}) error {
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

	h := sha256.New()
	h.Write([]byte(parts.Header + "." + parts.Claims))

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), decodedSignature); err != nil {
		return jwt.ErrInvalidSignature
	}

	decodedClaims, err := base64.RawURLEncoding.DecodeString(parts.Claims)
	if err != nil {
		return err
	}

	return json.Unmarshal(decodedClaims, v)
}

func Encode(priv *rsa.PrivateKey, v interface{}) ([]byte, error) {
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

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	return []byte(payload + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}

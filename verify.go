package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

const headerTypeJWT = "JWT"

type header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

func sign(alg string, sigLen int, v interface{}, fn func(data []byte) ([]byte, error)) ([]byte, error) {
	header, err := json.Marshal(header{Type: headerTypeJWT, Algorithm: alg})
	if err != nil {
		return nil, err
	}

	claims, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	i := base64.RawURLEncoding.EncodedLen(len(header))
	j := base64.RawURLEncoding.EncodedLen(len(claims))

	buf := make([]byte, i+1+j+1+base64.RawURLEncoding.EncodedLen(sigLen))
	base64.RawURLEncoding.Encode(buf, header)
	buf[i] = '.'
	base64.RawURLEncoding.Encode(buf[i+1:], claims)

	sig, err := fn(buf[:i+1+j])
	if err != nil {
		return nil, err
	}

	buf[i+1+j] = '.'
	base64.RawURLEncoding.Encode(buf[i+1+j+1:], sig)

	return buf, nil
}

func verify(alg string, s []byte, fn func(data, sig []byte) error) ([]byte, error) {
	i := bytes.IndexByte(s, '.')
	if i == -1 {
		return nil, ErrInvalidSignature
	}

	j := bytes.IndexByte(s[i+1:], '.')
	if j == -1 {
		return nil, ErrInvalidSignature
	}

	decodedHeader := make([]byte, base64.RawURLEncoding.DecodedLen(i))
	if _, err := base64.RawURLEncoding.Decode(decodedHeader, s[:i]); err != nil {
		return nil, err
	}

	var header header
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return nil, err
	}

	if header.Algorithm != alg {
		return nil, ErrInvalidSignature
	}

	decodedSignature := make([]byte, base64.RawURLEncoding.DecodedLen(len(s)-i-1-j-1))
	if _, err := base64.RawURLEncoding.Decode(decodedSignature, s[i+1+j+1:]); err != nil {
		return nil, err
	}

	if err := fn(s[:i+1+j], decodedSignature); err != nil {
		return nil, err
	}

	decodedClaims := make([]byte, base64.RawURLEncoding.DecodedLen(j))
	if _, err := base64.RawURLEncoding.Decode(decodedClaims, s[i+1:i+1+j]); err != nil {
		return nil, err
	}

	return decodedClaims, nil
}

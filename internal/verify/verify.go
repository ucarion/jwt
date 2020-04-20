package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/ucarion/jwt"
)

func Verify(alg string, s []byte, fn func(data, sig []byte) error) ([]byte, error) {
	i := bytes.IndexByte(s, '.')
	if i == -1 {
		return nil, jwt.ErrInvalidSignature
	}

	j := bytes.IndexByte(s[i+1:], '.')
	if j == -1 {
		return nil, jwt.ErrInvalidSignature
	}

	decodedHeader := make([]byte, base64.RawURLEncoding.DecodedLen(i))
	if _, err := base64.RawURLEncoding.Decode(decodedHeader, s[:i]); err != nil {
		return nil, err
	}

	var header jwt.Header
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return nil, err
	}

	if header.Algorithm != alg {
		return nil, jwt.ErrInvalidSignature
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

func Encode(alg string, v interface{}, fn func(data []byte) ([]byte, error)) ([]byte, error) {
	header, err := json.Marshal(jwt.Header{Type: jwt.HeaderTypeJWT, Algorithm: alg})
	if err != nil {
		return nil, err
	}

	claims, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	i := base64.RawURLEncoding.EncodedLen(len(header))
	j := base64.RawURLEncoding.EncodedLen(len(claims))

	data := make([]byte, i+1+j)
	base64.RawURLEncoding.Encode(data, header)
	data[i] = '.'
	base64.RawURLEncoding.Encode(data[i+1:], claims)

	sig, err := fn(data)
	if err != nil {
		return nil, err
	}

	k := base64.RawURLEncoding.EncodedLen(len(sig))
	out := make([]byte, i+1+j+1+k)
	copy(out, data)
	out[i+1+j] = '.'
	base64.RawURLEncoding.Encode(out[i+1+j+1:], sig)

	return out, nil
}

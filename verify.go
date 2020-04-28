package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// headerTypeJWT is the value used for "typ" in JWT headers.
const headerTypeJWT = "JWT"

// header represents a JWT header.
type header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

// sign encodes a header and body, has fn sign it, and then returns the
// resulting JWT.
//
// alg will be used as the "alg" field in the JWT header.
//
// sigLen must be the number of bytes that fn will return. Knowing this value in
// advance lets us avoid an extra allocation.
//
// v is encoded as JSON and used as the claims in the JWT.
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

	// We need i bytes for the header, j bytes for the claims, 2 bytes for two
	// period chars, and sigLen bytes for the signature.
	//
	// Here, we build the set of data we'll need to sign.
	buf := make([]byte, i+1+j+1+base64.RawURLEncoding.EncodedLen(sigLen))
	base64.RawURLEncoding.Encode(buf, header)
	buf[i] = '.' // i-1 is the last byte of the encoded header
	base64.RawURLEncoding.Encode(buf[i+1:], claims)

	// We need to sign the header, followed by a period, followed by the claims.
	sig, err := fn(buf[:i+1+j])
	if err != nil {
		return nil, err // if fn returns an error, we want to return that error
	}

	// We need to write out a period between the claims and the signature.
	buf[i+1+j] = '.' // i+1+j-1 is the last byte of the encoded claims
	base64.RawURLEncoding.Encode(buf[i+1+j+1:], sig)

	return buf, nil
}

// verify decodes a JWT into its parts, checks that it has the right alg, and
// then has fn verify the signature. If that succeeds, it returns the claims.
//
// alg is the expected value of the "alg" header. It's just a hoop to jump
// through, its value is otherwise ignored.
//
// fn will recieve the data that was supposed to be signed (the header, a
// period, and the claims), and the actual signature in the JWT. If the
// signature is invalid, fn must return an error.
func verify(alg string, s []byte, fn func(data, sig []byte) error) ([]byte, error) {
	// s[:i] will be the header
	i := bytes.IndexByte(s, '.')
	if i == -1 {
		return nil, ErrInvalidSignature
	}

	// s[i+1:s+1+j] will be the claims
	//
	// The rest of the data -- s[i+1+j+1:] -- will be the signature
	j := bytes.IndexByte(s[i+1:], '.')
	if j == -1 {
		return nil, ErrInvalidSignature
	}

	// decode the header's base64. It's stored as base64(json(...))
	decodedHeader := make([]byte, base64.RawURLEncoding.DecodedLen(i))
	if _, err := base64.RawURLEncoding.Decode(decodedHeader, s[:i]); err != nil {
		return nil, err
	}

	// decodedHeader now contains json(...), let's decode that into actual data
	var header header
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return nil, err
	}

	// This is just a hoop to jump through in order for a JWT to be accepted. We
	// require all JWTs to have the exact alg we want.
	if header.Algorithm != alg {
		return nil, ErrInvalidSignature
	}

	// decode the signature's base64.
	//
	// len(s)-(i+1+j+1) is the number of bytes in the signature, which starts at
	// index i+1+j+1.
	decodedSignature := make([]byte, base64.RawURLEncoding.DecodedLen(len(s)-i-1-j-1))
	if _, err := base64.RawURLEncoding.Decode(decodedSignature, s[i+1+j+1:]); err != nil {
		return nil, err
	}

	// The signature is expected to match the encoded header + period + claims.
	//
	// If get past this check without erroring, then the signature is valid.
	if err := fn(s[:i+1+j], decodedSignature); err != nil {
		return nil, err
	}

	// The signature is valid. It's stored as base64(json(...)), let's decode the
	// base64.
	//
	// The claims go from index i+1 to i+1+j -- it has length j.
	decodedClaims := make([]byte, base64.RawURLEncoding.DecodedLen(j))
	if _, err := base64.RawURLEncoding.Decode(decodedClaims, s[i+1:i+1+j]); err != nil {
		return nil, err
	}

	// We return the base64-decoded claims. Callers of this function will handle
	// doing json deserialization.
	return decodedClaims, nil
}

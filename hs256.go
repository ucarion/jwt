package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
)

const algHS256 = "HS256"

// SignHS256 takes a secret and a set of claims, and returns a HS256-signed JWT
// containing those claims.
//
// VerifyHS256 can verify tokens signed by SignHS256.
//
// When using SignHS256 and VerifyHS256 in production, use a long,
// randomly-generated secret. Do not leak or give out the secret to any systems
// or people that don't need it, because they will be able to generate JWTs that
// will be indistinguishable from the ones you can generate yourself.
//
// HS256 is short for HMAC SHA-256. It is a mechanism for message
// authentication. By signing a set of claims with SignHS256, you have not
// encrypted it. It is trivial for anyone to read the data stored in the return
// value of SignHS256. All SignHS256 gives you is a signature that proves that
// when you generated a JWT, you had a particular secret on hand -- and it does
// this without giving away what the secret is. VerifyHS256 can verify the JWTs
// produced by SignHS256; to do this, it needs to use the same secret you gave
// to SignHS256.
//
// The second parameter to this function, v, should be compatible with the
// encoding/json package of the standard library. The JSON representation of v
// will be used as the claims part of the returned JWT.
//
// SignHS256 will return an error only if calling json.Marshal on v returns an
// error.
func SignHS256(secret []byte, v interface{}) ([]byte, error) {
	return sign(algHS256, sha256.Size, v, func(data []byte) ([]byte, error) {
		h := hmac.New(sha256.New, secret)
		h.Write(data)

		return h.Sum(nil), nil
	})
}

// VerifyHS256 verifies a JWT using a secret. If the JWT is verified,
// VerifyHS256 will serialize the claims inside the JWT into v.
//
// The second parameter to this function, v, should be a pointer to something
// compatible with the encoding/json package of the standard library. If
// verification succeeds, VerifyHS256 will deserialize the claims in the JWT
// into v.
//
// VerifyHS256 will return InvalidSignature if the JWT is malformed, uses any
// algorithm other than HS256, or is not signed with the given secret.
func VerifyHS256(secret, s []byte, v interface{}) error {
	claims, err := verify(algHS256, s, func(data, sig []byte) error {
		h := hmac.New(sha256.New, secret)
		h.Write(data)

		if !hmac.Equal(h.Sum(nil), sig) {
			return ErrInvalidSignature
		}

		return nil
	})

	if err != nil {
		return err
	}

	return json.Unmarshal(claims, v)
}

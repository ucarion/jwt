package jwt

import "errors"

var ErrWrongAlgorithm = errors.New("jwt: wrong algorithm")
var ErrInvalidSignature = errors.New("jwt: invalid signature")

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

const HeaderTypeJWT = "JWT"

type StandardClaims struct {
	Issuer         string `json:"iss"`
	Subject        string `json:"subject"`
	Audience       string `json:"aud"`
	ExpirationTime uint64 `json:"exp"`
	NotBefore      uint64 `json:"nbf"`
	IssuedAt       uint64 `json:"iat"`
	ID             string `json:"jti"`
}

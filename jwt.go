// Package jwt implements JSON Web Tokens in a way that makes it easier to avoid
// common security mistakes.
//
// In particular, this package leaves out any support for features that
// frequently lead to security vulnerabilities in implementations of JWT. This
// package leaves out any support for the "none" algorithm, and does not support
// letting JWTs drive what algorithm is used for verification.
//
// When you use this package, you must specify exactly what algorithm you want
// to use, and only the three most widely-supported algorithms are permitted:
// HS256, RS256, and ES256. An attacker cannot trick you into accidentally
// reading a JWT without verifying it, and an attacker cannot trick you into
// using a different algorithm than you wanted.
//
// If you want to use a symmetric-key signature, see SignHS256 and VerifyHS256.
//
// If you want to use RSA public-key signatures, see SignRS256 and VerifyRS256.
//
// If you want to use ECDSA public-key signatures, see SignES256 and
// VerifyES256.
package jwt

import (
	"errors"
	"time"
)

// ErrInvalidSignature is the error returned by VerifyHS256, VerifyRS256, and
// VerifyES256 if there is anything wrong with the cryptographic signature on a
// JWT.
//
// This package intentionally provides no details beyond this error; for most
// applications, there is no reason to attempt to distinguish the various
// reasons a cryptographic signature on a JWT may be invalid.
//
// Some of the underlying reasons this error might be returned include:
//
// * The JWT was ill-formed. For instance, it may have been missing a header or
// a signature section.
//
// * The header section of the JWT indicated that the JWT was signed with the
// wrong algorithm.
//
// * The token was signed with the wrong secret.
//
// * Some of the data in the token was corrupted.
//
// Unless you know precisely what you're doing, you should usually treat any JWT
// that results in ErrInvalidSignature as an invalid request. You should usually
// not, in production systems, attempt to automatically dig into precisely what
// aspect of a JWT was invalid.
var ErrInvalidSignature = errors.New("jwt: invalid signature")

// StandardClaims is the set of claims registered by RFC7519.
//
// It is entirely possible and valid to use JWT but not use StandardClaims.
// StandardClaims is just a convenience struct to hold some of the most
// commonly-used claims in practice.
//
// If you would like to use claims in addition to those in StandardClaims,
// consider embedding StandardClaims in your own struct, like so:
//
//  type CustomClaims struct {
//    jwt.StandardClaims
//    MyCoolClaim string `json:"my_cool_claim"`
//  }
//
// In order to keep the JSON representation of this struct as terse as possible,
// all fields of this struct are omitted if left to their zero values.
//
// StandardClaims is just a convenience struct. Do not assume that the claims in
// StandardClaims carry any special meaning in the JWT spec. For more details on
// the standard JWT claims, see:
//
// https://tools.ietf.org/html/rfc7519#section-4.1
type StandardClaims struct {
	// Issuer identifies who issued the JWT.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// Subject identifies who the JWT is about.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// Audience identifies who is meant to process the JWT.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`

	// ExpirationTime indicates when the JWT expires. It should be a timestamp,
	// represented as seconds since the Unix epoch.
	//
	// VerifyExpirationTime can help you verify whether tokens have expired.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.4
	ExpirationTime int64 `json:"exp,omitempty"`

	// NotBefore indicates when the JWT becomes valid. It should be a timestamp,
	// represented as seconds since the Unix epoch.
	//
	// VerifyNotBefore can help you verify whether a token is valid yet.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.5
	NotBefore int64 `json:"nbf,omitempty"`

	// IssuedAt indicates when the JWT was issued. It should be a timestamp,
	// represented as seconds since the Unix epoch.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.6
	IssuedAt int64 `json:"iat,omitempty"`

	// ID is a unique identifier for the JWT.
	//
	// https://tools.ietf.org/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

// ErrExpiredToken is the error returned from VerifyExpirationTime and
// VerifyNotBefore when a JWT is not currently valid.
//
// When returned from VerifyExpirationTime, ErrExpiredToken error indicates that
// the JWT is expired.
//
// When returned from VerifyNotBefore, ErrExpiredToken error indicates that the
// JWT is not yet valid.
var ErrExpiredToken = errors.New("jwt: expired token")

// VerifyExpirationTime checks ExpirationTime ("exp") to see if a JWT has
// expired, and returns ErrExpiredToken if the token is expired.
//
// In production, you should usually pass time.Now() as the now argument to this
// function. But in your tests you may want to use a hard-coded time instead.
//
// VerifyExpirationTime assumes that you are using "exp" in the standard way
// described in RFC7519; if you are using "exp" in a nonstandard way, then
// VerifyExpirationTime is meaningless. In particular, VerifyExpirationTime
// assumes that ExpirationTime contains a Unix timestamp (seconds since epoch),
// and that if the current time is after ExpirationTime, then the token is no
// longer valid.
//
// If you are using VerifyExpirationTime to verify the validity of JWTs, please
// make sure you populate the ExpirationTime ("exp") field in StandardClaims by
// calling the Unix function on a time.Time instance. If you use UnixNano
// instead of Unix, VerifyExpirationTime will return invalid results.
func (s *StandardClaims) VerifyExpirationTime(now time.Time) error {
	if now.After(time.Unix(s.ExpirationTime, 0)) {
		return ErrExpiredToken
	}

	return nil
}

// VerifyNotBefore checks NotBefore ("nbf") to see if a JWT is not yet valid,
// and returns ErrExpiredToken if the token is not yet valid.
//
// In production, you should usually pass time.Now() as the now argument to this
// function. But in your tests you may want to use a hard-coded time instead.
//
// VerifyNotBefore assumes that you are using "nbf" in the standard way
// described in RFC7519; if you are using "nbf" in a nonstandard way, then
// VerifyNotBefore is meaningless. In particular, VerifyNotBefore assumes that
// NotBefore contains a Unix timestamp (seconds since epoch), and that if the
// current time is before NotBefore, then the token is not yet valid.
//
// If you are using VerifyNotBefore to verify the validity of JWTs, please make
// sure you populate the NotBefore ("nbf") field in StandardClaims by calling
// the Unix function on a time.Time instance. If you use UnixNano instead of
// Unix, VerifyNotBefore will return invalid results.
func (s *StandardClaims) VerifyNotBefore(now time.Time) error {
	if now.Before(time.Unix(s.NotBefore, 0)) {
		return ErrExpiredToken
	}

	return nil
}

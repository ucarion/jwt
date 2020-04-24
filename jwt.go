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
// From RFC7519:
//
//  The following Claim Names are registered in the IANA "JSON Web Token
//  Claims" registry established by Section 10.1.  None of the claims
//  defined below are intended to be mandatory to use or implement in all
//  cases, but rather they provide a starting point for a set of useful,
//  interoperable claims.  Applications using JWTs should define which
//  specific claims they use and when they are required or optional.  All
//  the names are short because a core goal of JWTs is for the
//  representation to be compact.
//
// StandardClaims is just a convenience struct. Do not assume that the claims in
// StandardClaims carry any special meaning in the JWT spec.
type StandardClaims struct {
	// From RFC7519:
	//
	//	The "iss" (issuer) claim identifies the principal that issued the
	//	JWT.  The processing of this claim is generally application specific.
	//	The "iss" value is a case-sensitive string containing a StringOrURI
	//	value.  Use of this claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
	Issuer string `json:"iss,omitempty"`

	// From RFC7519:
	//
	//	The "sub" (subject) claim identifies the principal that is the
	//	subject of the JWT.  The claims in a JWT are normally statements
	//	about the subject.  The subject value MUST either be scoped to be
	//	locally unique in the context of the issuer or be globally unique.
	//	The processing of this claim is generally application specific.  The
	//	"sub" value is a case-sensitive string containing a StringOrURI
	//	value.  Use of this claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
	Subject string `json:"sub,omitempty"`

	// From RFC7519:
	//
	//	The "aud" (audience) claim identifies the recipients that the JWT is
	//	intended for.  Each principal intended to process the JWT MUST
	//	identify itself with a value in the audience claim.  If the principal
	//	processing the claim does not identify itself with a value in the
	//	"aud" claim when this claim is present, then the JWT MUST be
	//	rejected.  In the general case, the "aud" value is an array of case-
	//	sensitive strings, each containing a StringOrURI value.  In the
	//	special case when the JWT has one audience, the "aud" value MAY be a
	//	single case-sensitive string containing a StringOrURI value.  The
	//	interpretation of audience values is generally application specific.
	//	Use of this claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
	Audience string `json:"aud,omitempty"`

	// From RFC7519:
	//
	//  The "exp" (expiration time) claim identifies the expiration time on
	//  or after which the JWT MUST NOT be accepted for processing.  The
	//  processing of the "exp" claim requires that the current date/time
	//  MUST be before the expiration date/time listed in the "exp" claim.
	//	Implementers MAY provide for some small leeway, usually no more than
	//	a few minutes, to account for clock skew.  Its value MUST be a number
	//	containing a NumericDate value.  Use of this claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
	//
	// See VerifyExpirationTime for a function you can use to validate this claim,
	// if you choose to use it in the typical manner.
	ExpirationTime int64 `json:"exp,omitempty"`

	// From RFC7519:
	//
	//  The "nbf" (not before) claim identifies the time before which the JWT
	//  MUST NOT be accepted for processing.  The processing of the "nbf"
	//  claim requires that the current date/time MUST be after or equal to
	//  the not-before date/time listed in the "nbf" claim.  Implementers MAY
	//  provide for some small leeway, usually no more than a few minutes, to
	//  account for clock skew.  Its value MUST be a number containing a
	//  NumericDate value.  Use of this claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
	//
	// See VerifyNotBefore for a function you can use to validate this claim, if
	// you choose to use it in the typical manner.
	NotBefore int64 `json:"nbf,omitempty"`

	// From RFC7519:
	//
	//	The "iat" (issued at) claim identifies the time at which the JWT was
	//	issued.  This claim can be used to determine the age of the JWT.  Its
	//	value MUST be a number containing a NumericDate value.  Use of this
	//	claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
	IssuedAt int64 `json:"iat,omitempty"`

	// From RFC7519:
	//
	//	The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	//	The identifier value MUST be assigned in a manner that ensures that
	//	there is a negligible probability that the same value will be
	//	accidentally assigned to a different data object; if the application
	//	uses multiple issuers, collisions MUST be prevented among values
	//	produced by different issuers as well.  The "jti" claim can be used
	//	to prevent the JWT from being replayed.  The "jti" value is a case-
	//	sensitive string.  Use of this claim is OPTIONAL.
	//
	// Like all other claims in JWT, this claim does not necessarily have a
	// special meaning across systems. You may do anything with this claim that
	// you please, just as other systems may do.
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
//
// From RFC7519:
//
//  The "exp" (expiration time) claim identifies the expiration time on
//  or after which the JWT MUST NOT be accepted for processing.  The
//  processing of the "exp" claim requires that the current date/time
//  MUST be before the expiration date/time listed in the "exp" claim.
//  Implementers MAY provide for some small leeway, usually no more than
//  a few minutes, to account for clock skew.  Its value MUST be a number
//  containing a NumericDate value.  Use of this claim is OPTIONAL.
//
// This package does not implement the "small leeway" described in the spec. If
// you want to tolerate a slightly-expired token, you should adjust "now" to be
// a bit after time.Now.
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
//
// From RFC7519:
//
//  The "nbf" (not before) claim identifies the time before which the JWT
//  MUST NOT be accepted for processing.  The processing of the "nbf"
//  claim requires that the current date/time MUST be after or equal to
//  the not-before date/time listed in the "nbf" claim.  Implementers MAY
//  provide for some small leeway, usually no more than a few minutes, to
//  account for clock skew.  Its value MUST be a number containing a
//  NumericDate value.  Use of this claim is OPTIONAL.
//
// This package does not implement the "small leeway" described in the spec. If
// you want to tolerate a soon-to-be-valid token, you should adjust "now" to be
// a bit before time.Now.
func (s *StandardClaims) VerifyNotBefore(now time.Time) error {
	if now.Before(time.Unix(s.NotBefore, 0)) {
		return ErrExpiredToken
	}

	return nil
}

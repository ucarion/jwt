package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/jwt"
)

// zeroReader is used to seed crypto/rand.Reader in some examples.
type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func ExampleStandardClaims() {
	type CustomClaims struct {
		jwt.StandardClaims
		MyCoolClaim string `json:"my_cool_claim"`
	}

	s, _ := json.Marshal(CustomClaims{
		StandardClaims: jwt.StandardClaims{Subject: "john@example.com"},
		MyCoolClaim:    "asdf",
	})

	fmt.Println(string(s))
	// Output:
	//
	// {"sub":"john@example.com","my_cool_claim":"asdf"}
}

func TestVerifyExpirationTime(t *testing.T) {
	claims := jwt.StandardClaims{ExpirationTime: 1}
	assert.NoError(t, claims.VerifyExpirationTime(time.Unix(0, 0)))
	assert.Equal(t, jwt.ErrExpiredToken, claims.VerifyExpirationTime(time.Unix(2, 0)))
}

func TestVerifyNotBefore(t *testing.T) {
	claims := jwt.StandardClaims{NotBefore: 1}
	assert.Equal(t, jwt.ErrExpiredToken, claims.VerifyNotBefore(time.Unix(0, 0)))
	assert.NoError(t, claims.VerifyNotBefore(time.Unix(2, 0)))
}

func ExampleStandardClaims_VerifyExpirationTime() {
	exp, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:40-07:00")
	claims := jwt.StandardClaims{ExpirationTime: exp.Unix()}

	// nowBeforeExp is one second before exp
	nowBeforeExp, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:39-07:00")
	fmt.Println(claims.VerifyExpirationTime(nowBeforeExp))

	// nowAfterExp is one second after exp
	nowAfterExp, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:41-07:00")
	fmt.Println(claims.VerifyExpirationTime(nowAfterExp))
	// Output:
	//
	// <nil>
	// jwt: expired token
}

func ExampleStandardClaims_VerifyExpirationTime_unixNano() {
	// This is an example of what happens if you use UnixNano instead of Unix.
	// Tokens expire much later than intended. This is probably a serious security
	// flaw if you implement this in a production system.
	//
	// This example is here to clarify how serious a mistake it would be to use
	// UnixNano instead of Unix in ExpirationTime, and then pass that to
	// VerifyExpirationTime.
	exp, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:40-07:00")
	claims := jwt.StandardClaims{ExpirationTime: exp.UnixNano()} // DO NOT DO THIS

	// nowBeforeExp is one second before exp, but we used UnixNano instead of Unix
	// so VerifyExpirationTime is returning nonsense values anyway.
	nowBeforeExp, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:39-07:00")
	fmt.Println(claims.VerifyExpirationTime(nowBeforeExp))

	// nowAfterExp is one second before exp, but we used UnixNano instead of Unix
	// so VerifyExpirationTime is returning nonsense values anyway.
	//
	// In this case, we are failing to detect that the token is expired.
	nowAfterExp, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:41-07:00")
	fmt.Println(claims.VerifyExpirationTime(nowAfterExp))
	// Output:
	//
	// <nil>
	// <nil>
}

func ExampleStandardClaims_VerifyNotBefore() {
	nbf, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:40-07:00")
	claims := jwt.StandardClaims{NotBefore: nbf.Unix()}

	// nowBeforeNbf is one second before nbf
	nowBeforeNbf, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:39-07:00")
	fmt.Println(claims.VerifyNotBefore(nowBeforeNbf))

	// nowAfterNbf is one second after nbf
	nowAfterNbf, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:41-07:00")
	fmt.Println(claims.VerifyNotBefore(nowAfterNbf))
	// Output:
	//
	// jwt: expired token
	// <nil>
}

func ExampleStandardClaims_VerifyNotBefore_unixNano() {
	// This is an example of what happens if you use UnixNano instead of Unix.
	// Tokens are valid much later than intended. This could be a serious security
	// flaw if you implement this in a production system.
	//
	// This example is here to clarify how serious a mistake it would be to use
	// UnixNano instead of Unix in NotBefore, and then pass that to
	// VerifyNotBefore.
	nbf, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:40-07:00")
	claims := jwt.StandardClaims{NotBefore: nbf.UnixNano()} // DO NOT DO THIS

	// nowBeforeExp is one second before exp, but we used UnixNano instead of Unix
	// so VerifyNotBefore is returning nonsense values anyway.
	//
	// In this case, we are failing to detect that the token is expired.
	nowBeforeNbf, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:39-07:00")
	fmt.Println(claims.VerifyNotBefore(nowBeforeNbf))

	// nowAfterExp is one second before exp, but we used UnixNano instead of Unix
	// so VerifyNotBefore is returning nonsense values anyway.
	//
	// In this case, we are mistakenly rejecting a token that we should accept.
	nowAfterNbf, _ := time.Parse(time.RFC3339, "2015-05-19T16:45:41-07:00")
	fmt.Println(claims.VerifyNotBefore(nowAfterNbf))
	// Output:
	//
	// jwt: expired token
	// jwt: expired token
}

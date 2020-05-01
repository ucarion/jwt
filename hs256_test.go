package jwt_test

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/jwt"
)

func TestVerifyHS256(t *testing.T) {
	// This key is from:
	//
	// https://tools.ietf.org/html/rfc7515#appendix-A.1.1
	encodedKey := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	assert.NoError(t, err)

	// This JWT is from:
	//
	// https://tools.ietf.org/html/rfc7519#section-3.1
	//
	// It also appears in RFC7515.
	s := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	var claims map[string]interface{}
	assert.NoError(t, jwt.VerifyHS256(key, []byte(s), &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func TestSignHS256(t *testing.T) {
	// We can't reproduce exactly the same JWT that appears in the RFC, because
	// the RFC uses claims with some weird JSON indentation.
	encodedKey := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	assert.NoError(t, err)

	encoded, err := jwt.SignHS256(key, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	})

	assert.NoError(t, err)
	assert.Equal(t, encoded, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.LGyv4nF987S4V9z9qm-803XzhHTFe0o82-JsLGEZCjQ"))

	// Ensure it round-trips back to the original claims.
	var claims map[string]interface{}
	assert.NoError(t, jwt.VerifyHS256(key, encoded, &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func ExampleSignHS256() {
	secret := []byte("my secret key")
	claims := jwt.StandardClaims{Subject: "jdoe@example.com"}
	token, err := jwt.SignHS256(secret, claims)
	fmt.Println(string(token), err)
	// Output:
	//
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.-xGQG6ofJdrrdhlOoI0irQSMufJQQEv3fKwdrx4D4I8 <nil>
}

func ExampleSignHS256_underTheHood() {
	// In this example, we'll see exactly how the bytes that make up a HS256 JWT
	// are constructed. Hopefully, this will clarify exactly what is going on when
	// you create a JWT using HS256.

	secret := []byte("my secret key")
	claims := jwt.StandardClaims{Subject: "jdoe@example.com"}
	token, err := jwt.SignHS256(secret, claims)

	// The header part of the token is going to be the unpadded, URL-safe base64
	// encoding of '{"typ":"JWT","alg":"HS256"}':
	//
	// $ echo -n '{"typ":"JWT","alg":"HS256"}' | base64 | tr +/ -_ | tr -d =
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
	//
	// The claims part of the token is going to be the unpadded, URL-safe base64
	// encoding of '{"sub":"jdoe@example.com"}':
	//
	// $ echo -n '{"sub":"jdoe@example.com"}' | base64 | tr +/ -_ | tr -d =
	// eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0
	//
	// Finally, the signature part is going to be HMAC-SHA256 of the header part
	// and the claims part concatenated together, with a period ('.') in between
	// them:
	//
	// $ echo -n \
	//  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0 \
	//  | openssl dgst -sha256 -hmac "my secret key" -binary \
	//  | base64 | tr +/ -_ | tr -d =
	//
	// -xGQG6ofJdrrdhlOoI0irQSMufJQQEv3fKwdrx4D4I8
	//
	// Putting the header, claims, and signature together, with periods ('.')
	// between them, you get the final JWT:

	fmt.Println(string(token))
	fmt.Println(err)
	// Output:
	//
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.-xGQG6ofJdrrdhlOoI0irQSMufJQQEv3fKwdrx4D4I8
	// <nil>
}

func ExampleVerifyHS256() {
	// This JWT is the output of the SignHS256 example
	token := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.-xGQG6ofJdrrdhlOoI0irQSMufJQQEv3fKwdrx4D4I8")

	secret := []byte("my secret key")
	var claims jwt.StandardClaims
	err := jwt.VerifyHS256(secret, token, &claims)
	fmt.Println(claims, err)
	// Output:
	//
	// { jdoe@example.com  0 0 0 } <nil>
}

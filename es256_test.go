package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/jwt"
)

func TestVerifyES256(t *testing.T) {
	// The token and key in this test are from:
	//
	// https://tools.ietf.org/html/rfc7515#appendix-A.3
	s := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	encodedX := "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	decodedX, err := base64.RawURLEncoding.DecodeString(encodedX)
	assert.NoError(t, err)

	var x big.Int
	x.SetBytes(decodedX)

	encodedY := "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	decodedY, err := base64.RawURLEncoding.DecodeString(encodedY)
	assert.NoError(t, err)

	var y big.Int
	y.SetBytes(decodedY)

	publicKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: &x, Y: &y}
	var claims map[string]interface{}
	assert.NoError(t, jwt.VerifyES256(&publicKey, []byte(s), &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func TestEncodeES256(t *testing.T) {
	encodedX := "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	decodedX, err := base64.RawURLEncoding.DecodeString(encodedX)
	assert.NoError(t, err)

	var x big.Int
	x.SetBytes(decodedX)

	encodedY := "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	decodedY, err := base64.RawURLEncoding.DecodeString(encodedY)
	assert.NoError(t, err)

	var y big.Int
	y.SetBytes(decodedY)

	encodedD := "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
	decodedD, err := base64.RawURLEncoding.DecodeString(encodedD)
	assert.NoError(t, err)

	var d big.Int
	d.SetBytes(decodedD)

	publicKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: &x, Y: &y}
	privateKey := ecdsa.PrivateKey{PublicKey: publicKey, D: &d}

	encoded, err := jwt.SignES256(&privateKey, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	})

	assert.NoError(t, err)

	// Ensure it round-trips back to the original claims.
	var claims map[string]interface{}
	assert.NoError(t, jwt.VerifyES256(&publicKey, encoded, &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func ExampleSignES256() {
	// You can generate PEM files like this by running:
	//
	// openssl ecparam -genkey -name prime256v1 -noout -out mykey.pem
	pemPrivateKey := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINjhxbMoJfxovy0ivk1UAe0DAs+BFnL0NmzNabfTZq/FoAoGCCqGSM49
AwEHoUQDQgAEm3MpqIDa7nhiqKA2TaiijXLIaOX2+RA1gl4SPWnRYULdqJUhdrw0
UmRjl6SsX9iLp1UmC9xuFws6cUYrEkn2iQ==
-----END EC PRIVATE KEY-----`

	pemBlock, _ := pem.Decode([]byte(pemPrivateKey))
	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	fmt.Println(err)

	// DO NOT DO THIS IN PRODUCTION
	//
	// This line is *just* here to make the output of SignES256 predictable. The
	// default value for crypto/rand.Reader is a good one that you should not
	// reassign. ECDSA signing uses a random seed, which makes the result of ECDSA
	// signatures otherwise unpredictable. This is a good thing in the real world.
	// It's only inconvenient in examples like these, where the output needs to be
	// predicatable in order for tests to pass.
	//
	// Everything after this assignment to rand.Reader is appropriate usage of
	// this package.
	//
	// Again: DO NOT REASSIGN TO rand.Reader IN REAL-WORLD CODE!
	rand.Reader = zeroReader{}

	claims := jwt.StandardClaims{Subject: "jdoe@example.com"}
	token, err := jwt.SignES256(privateKey, claims)
	fmt.Println(err)
	fmt.Println(string(token))
	// Output:
	//
	// <nil>
	// <nil>
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.ct8SDmgHHubv1jPDeUVIi8C3sNcP0PASq2CBABGH1vG0OVhS6gaAeJuGKubScJYCAP9K5HbykBOGTcgGb_bs5Q
}

func ExampleVerifyES256() {
	// You can generate PEM files like this by running:
	//
	// openssl ecparam -genkey -name prime256v1 -noout -out mykey.pem
	// openssl ec -in mykey.pem -pubout
	//
	// This public key corresponds to the private key in ExampleSignES256.
	pemPublicKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm3MpqIDa7nhiqKA2TaiijXLIaOX2
+RA1gl4SPWnRYULdqJUhdrw0UmRjl6SsX9iLp1UmC9xuFws6cUYrEkn2iQ==
-----END PUBLIC KEY-----`

	pemBlock, _ := pem.Decode([]byte(pemPublicKey))
	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	fmt.Println(err)

	// This JWT is from ExampleSignES256
	token := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.i-WuJB9hr3XVLMT_mfbraTD2l0HCSi6iWodsgjyXlwsy7ZyXe6cUSfBhSI29USpzXajiy5sloueHyBGbPz3C-w")

	var claims jwt.StandardClaims
	err = jwt.VerifyES256(publicKey.(*ecdsa.PublicKey), token, &claims)
	fmt.Println(err)
	fmt.Println(claims)
	// Output:
	//
	// <nil>
	// <nil>
	// { jdoe@example.com  0 0 0 }
}

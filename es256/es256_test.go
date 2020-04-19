package es256_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/jwt/es256"
)

func TestValidate(t *testing.T) {
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
	assert.NoError(t, es256.Validate(&publicKey, []byte(s), &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func TestEncode(t *testing.T) {
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

	encoded, err := es256.Encode(&privateKey, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	})

	assert.NoError(t, err)

	// Ensure it round-trips back to the original claims.
	var claims map[string]interface{}
	assert.NoError(t, es256.Validate(&publicKey, encoded, &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

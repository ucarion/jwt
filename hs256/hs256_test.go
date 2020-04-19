package hs256_test

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/jwt/hs256"
)

func TestValidate(t *testing.T) {
	encodedKey := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	assert.NoError(t, err)

	s := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	var claims map[string]interface{}
	assert.NoError(t, hs256.Validate(key, []byte(s), &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func TestEncode(t *testing.T) {
	encodedKey := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	assert.NoError(t, err)

	encoded, err := hs256.Encode(key, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	})

	assert.NoError(t, err)
	assert.Equal(t, encoded, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.LGyv4nF987S4V9z9qm-803XzhHTFe0o82-JsLGEZCjQ"))

	// Ensure it round-trips back to the original claims.
	var claims map[string]interface{}
	assert.NoError(t, hs256.Validate(key, encoded, &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

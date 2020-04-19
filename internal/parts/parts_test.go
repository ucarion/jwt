package parts_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ucarion/jwt/internal/parts"
)

func TestParseOK(t *testing.T) {
	s := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	p, err := parts.Parse([]byte(s))
	assert.NoError(t, err)
	assert.Equal(t, p, parts.Parts{
		Header:    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
		Claims:    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
		Signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
}

func TestParseErr(t *testing.T) {
	s := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	_, err := parts.Parse([]byte(s))
	assert.Equal(t, parts.ErrNotEnoughParts, err)
}

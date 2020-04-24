package jwt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	// echo -n '{"alg": "test"}' | base64 | tr -d =
	// echo -n 'claims' | base64 | tr -d =
	// echo -n 'sig' | base64 | tr -d =
	claims, err := verify("test", []byte("eyJhbGciOiAidGVzdCJ9.Y2xhaW1z.c2ln"), func(data, sig []byte) error {
		assert.Equal(t, []byte("eyJhbGciOiAidGVzdCJ9.Y2xhaW1z"), data)
		assert.Equal(t, []byte("sig"), sig)
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, []byte("claims"), claims)

	_, err = verify("not-test", []byte("eyJhbGciOiAidGVzdCJ9.Y2xhaW1z.c2lnCg"), func(data, sig []byte) error {
		t.Fail()
		return nil
	})

	assert.Equal(t, ErrInvalidSignature, err)

	testErr := errors.New("test error")
	_, err = verify("test", []byte("eyJhbGciOiAidGVzdCJ9.Y2xhaW1z.c2lnCg"), func(data, sig []byte) error {
		return testErr
	})

	assert.Equal(t, testErr, err)
}

func TestSign(t *testing.T) {
	s, err := sign("test", 3, true, func(data []byte) ([]byte, error) {
		// echo -n '{"typ":"JWT","alg":"test"}' | base64 | tr -d =
		// echo -n 'true' | base64 | tr -d =
		assert.Equal(t, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.dHJ1ZQ"), data)
		return []byte("sig"), nil
	})

	assert.NoError(t, err)
	assert.Equal(t, []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJ0ZXN0In0.dHJ1ZQ.c2ln"), s)

	testErr := errors.New("test error")
	_, err = sign("test", 3, true, func(data []byte) ([]byte, error) {
		return nil, testErr
	})

	assert.Equal(t, err, testErr)
}

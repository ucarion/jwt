package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
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

func TestVerifyRS256(t *testing.T) {
	s := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

	encodedN := "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
	decodedN, err := base64.RawURLEncoding.DecodeString(encodedN)
	assert.NoError(t, err)

	var n big.Int
	n.SetBytes(decodedN)

	encodedE := "AQAB"
	decodedE, err := base64.RawURLEncoding.DecodeString(encodedE)
	assert.NoError(t, err)

	var e big.Int
	e.SetBytes(decodedE)

	publicKey := rsa.PublicKey{N: &n, E: int(e.Uint64())}

	var claims map[string]interface{}
	assert.NoError(t, jwt.VerifyRS256(&publicKey, []byte(s), &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func TestSignRS256(t *testing.T) {
	encodedN := "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
	decodedN, err := base64.RawURLEncoding.DecodeString(encodedN)
	assert.NoError(t, err)

	var n big.Int
	n.SetBytes(decodedN)

	encodedE := "AQAB"
	decodedE, err := base64.RawURLEncoding.DecodeString(encodedE)
	assert.NoError(t, err)

	var e big.Int
	e.SetBytes(decodedE)

	encodedD := "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
	decodedD, err := base64.RawURLEncoding.DecodeString(encodedD)
	assert.NoError(t, err)

	var d big.Int
	d.SetBytes(decodedD)

	encodedP := "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
	decodedP, err := base64.RawURLEncoding.DecodeString(encodedP)
	assert.NoError(t, err)

	var p big.Int
	p.SetBytes(decodedP)

	encodedQ := "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
	decodedQ, err := base64.RawURLEncoding.DecodeString(encodedQ)
	assert.NoError(t, err)

	var q big.Int
	q.SetBytes(decodedQ)

	publicKey := rsa.PublicKey{N: &n, E: int(e.Uint64())}
	privateKey := rsa.PrivateKey{
		PublicKey: publicKey,
		D:         &d,
		Primes:    []*big.Int{&p, &q},
	}

	encoded, err := jwt.SignRS256(&privateKey, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	})

	assert.NoError(t, err)

	// Ensure it round-trips back to the original claims.
	var claims map[string]interface{}
	assert.NoError(t, jwt.VerifyRS256(&publicKey, encoded, &claims))
	assert.True(t, reflect.DeepEqual(claims, map[string]interface{}{
		"iss":                        "joe",
		"exp":                        1300819380.0,
		"http://example.com/is_root": true,
	}))
}

func ExampleSignRS256() {
	// You can generate PEM files like this by running:
	//
	// openssl genrsa -out mykey.pem 2048
	pemPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAlMhK8kfH33aII60/eOhk8Kic4FSmdmZ8Rp1M0zcGr9G5dXMl
Wf6FP+mAhB1olpxeP7UyF9iG0pL8lD3NkXWnrCrwoh9rebI2JKbXMTTNXJazcJvB
FcODL+ueEPUSLzJZw7CypJF2ak7O7iniDFRCxQt/y7uUpST40bINt1SqBZtLJkzl
N6G8CZufgADePdFcY7ONWUYcfEiAozpV5thu4PBW3ShX5ExE4Ni894zKZ25VSyB7
gHO+/fWmxkmAeu6oSzzlcN88qptmwzsW6RF+Cmf5zHqepSeEdU5ZVwlSX9hgBWIO
QKzz+pqdh0Yzp85BugBWLXLPEWgwwFou5aYiwQIDAQABAoIBAQCHufh08Xqqpq0n
LsL6f7alvIvwMgjxdijlGladUFNvTTmMpZBrer8AQPmWjGV/EAMCxz99dW/45VI5
we+oRNbDPyDqJROcnzC5WuJw5yR41Jm5nr0UJ5mju6QlAAyotZwh4y305yZJcL9h
kR+/85Y9v3HD38mIpiO+2Fme50N7fH2Ipz0oDKmp8yMXDQbnlqwZi+ATnT4jGoIe
LfbJIiENiBpX2cFqHYGTmEXvqUi/rsjYERPi5BZnrDIMLWcD3PDKlet3z8Zr97s5
QSV6ff4aVLdQp130YZVG2Yom4vpS8XdcWI75VXuymfhLttDbLoF/wm/er7rrri7A
aVpv1G5JAoGBAMTPVPwVaxYyTnIzRene3e0JdWe7pmKLpcLFjLjMFRgck+kt+al3
bFFCfaHavj3bb34zuAKSkULMs3nnG0nLeccApVb5F8wrtk6Ta0l86ox1ZHcPP1ju
+1A4I8UfSNh8pBcHjHOKRaIPtneFxZqeuAECdSKCMMguUvhe3j6UtEQjAoGBAMGH
Qb2ddP57rFEy3evLuym+j2ThF9PEZFcLiZKgUBOwCLVhnD3/z1SZiyscMY3jIopu
uclesC8Vk9VDAOFBWdmCQ0MUyt0uU0Ww5Lq6pG+qqxKzXyBs8ecTmAEAvcGVqvQX
DivyoaK1dDtbYlBASKpZ7HjRRlGvvNs2OkAKc6nLAoGAemgdil/j571ILx0WubvE
ud3tKKR8esQyR67ItFMyN3nmwNu4cR92vh+ltdowApcNhCe0pdz0/eAFLKeBwGcO
iagsLajllTYGwF5OFznbQ5rr7mUMWErjAeS40qx/iS4UfMJUJ7RzVLWDHlmUKnPX
K8GUiu8AWjD9p76RacjhSZMCgYAPbSCoZKy2vFT4A/38lbjNkwsLF4Y2syjsZ1cI
AQ9hAl8vViCGMKXuMG8PeKfaj4hpUHouuwWAO1AVZ8niKrtmwyNpbXbeOpsYqwkQ
eWAyJoCMdQ/YHdcKfF1Zdx2pGK0P1+ahSi3oMl6ZfKdRjk48hf57gvL//+ol7ySl
hi/CEQKBgCWo5eG5p/j3fBTWwXHpHUTerKwxSIJW5v6oANQSxre0LKpZ4JvqFPjZ
r/tmLxnUo6u20pAz5qEY9ST7rmk4JIbueKb6dNAe2iePdL75YwUxULTrD3c9IETd
d1GiozKs/3biveU5QDtciiMi7KTgyPuY19sdEH/I2BrTT0Ose63T
-----END RSA PRIVATE KEY-----`

	pemBlock, _ := pem.Decode([]byte(pemPrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	fmt.Println(err)

	// DO NOT DO THIS IN PRODUCTION
	//
	// This line is *just* here to make the output of SignRS256 predictable. The
	// default value for crypto/rand.Reader is a good one that you should not
	// reassign. RSA signing uses a random seed, which makes the result of RSA
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
	token, err := jwt.SignRS256(privateKey, claims)
	fmt.Println(err)
	fmt.Println(string(token))
	// Output:
	//
	// <nil>
	// <nil>
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.SdhqDUZjbr4dBe7XlpUPJAgWPIFCs5UxtcUsqJeH_OW-To0stN1Rhps2FG0JzUS8HFCY_6gjoO57UrrO7qu13eglexKxIloZ6Wg3g7wL1eTI8XxawMbhm1BCNBKpriAQ82CiE0FqyW7326fBKY9ijE6A04W8lpA97SYlBIH5d6Q9QehPxXwdvhTUrrYLsU8OqzSC8LuveCxk4mtUXNRyrw-juIlnVCrjB13NX5TRQpXHMbSR2KkHsLuUpIhhDYcGt3AIT2rqWlFgC-sikVdHRODL6p0nRmxo9-lJYNT_l_PAJrCfzawQ8pJR0Tuc89_6mdL8QXs0yU91lfj93VRRZg
}

func ExampleVerifyRS256() {
	// You can generate PEM files like this by running:
	//
	// openssl genrsa -out mykey.pem 2048
	// openssl rsa -in mykey.pem -pubout -RSAPublicKey_out
	//
	// This public key corresponds to the private key in ExampleSignRS256.
	pemPublicKey := `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAlMhK8kfH33aII60/eOhk8Kic4FSmdmZ8Rp1M0zcGr9G5dXMlWf6F
P+mAhB1olpxeP7UyF9iG0pL8lD3NkXWnrCrwoh9rebI2JKbXMTTNXJazcJvBFcOD
L+ueEPUSLzJZw7CypJF2ak7O7iniDFRCxQt/y7uUpST40bINt1SqBZtLJkzlN6G8
CZufgADePdFcY7ONWUYcfEiAozpV5thu4PBW3ShX5ExE4Ni894zKZ25VSyB7gHO+
/fWmxkmAeu6oSzzlcN88qptmwzsW6RF+Cmf5zHqepSeEdU5ZVwlSX9hgBWIOQKzz
+pqdh0Yzp85BugBWLXLPEWgwwFou5aYiwQIDAQAB
-----END RSA PUBLIC KEY-----`

	pemBlock, _ := pem.Decode([]byte(pemPublicKey))
	publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	fmt.Println(err)

	// This JWT is from ExampleSignRS256
	token := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJqZG9lQGV4YW1wbGUuY29tIn0.SdhqDUZjbr4dBe7XlpUPJAgWPIFCs5UxtcUsqJeH_OW-To0stN1Rhps2FG0JzUS8HFCY_6gjoO57UrrO7qu13eglexKxIloZ6Wg3g7wL1eTI8XxawMbhm1BCNBKpriAQ82CiE0FqyW7326fBKY9ijE6A04W8lpA97SYlBIH5d6Q9QehPxXwdvhTUrrYLsU8OqzSC8LuveCxk4mtUXNRyrw-juIlnVCrjB13NX5TRQpXHMbSR2KkHsLuUpIhhDYcGt3AIT2rqWlFgC-sikVdHRODL6p0nRmxo9-lJYNT_l_PAJrCfzawQ8pJR0Tuc89_6mdL8QXs0yU91lfj93VRRZg")

	var claims jwt.StandardClaims
	err = jwt.VerifyRS256(publicKey, token, &claims)
	fmt.Println(err)
	fmt.Println(claims)
	// Output:
	//
	// <nil>
	// <nil>
	// { jdoe@example.com  0 0 0 }
}

package jwt_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	jwt_dgrijalva "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	jwt_ucarion "github.com/ucarion/jwt"
)

func BenchmarkJWT(b *testing.B) {
	b.Run("hs256", func(b *testing.B) {
		key := "8a5a91a441a7fd7292e7f9bbfb153e0c18c8dcd03c6b46e605727bfcc73f7abf"

		b.Run("sign", func(b *testing.B) {
			b.Run("ucarion", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					claims := jwt_ucarion.StandardClaims{
						Subject:        "jdoe@example.com",
						NotBefore:      time.Now().Add(-time.Hour).Unix(),
						ExpirationTime: time.Now().Add(time.Hour).Unix(),
					}

					_, err := jwt_ucarion.SignHS256([]byte(key), claims)
					assert.NoError(b, err)
				}
			})

			b.Run("dgrijalva", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					claims := jwt_dgrijalva.StandardClaims{
						Subject:   "jdoe@example.com",
						NotBefore: time.Now().Add(-time.Hour).Unix(),
						ExpiresAt: time.Now().Add(time.Hour).Unix(),
					}

					token := jwt_dgrijalva.NewWithClaims(jwt_dgrijalva.SigningMethodHS256, claims)
					_, err := token.SignedString([]byte(key))
					assert.NoError(b, err)
				}
			})
		})

		b.Run("verify", func(b *testing.B) {
			// First, generate the token we'll verify.
			token, err := jwt_ucarion.SignHS256([]byte(key), jwt_ucarion.StandardClaims{
				Subject:        "jdoe@example.com",
				NotBefore:      time.Now().Add(-time.Hour).Unix(),
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
			})

			assert.NoError(b, err)

			// dgrijalva/jwt-go parses JWTs as strings, not []byte
			tokenString := string(token)

			b.Run("ucarion", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					var claims jwt_ucarion.StandardClaims
					assert.NoError(b, jwt_ucarion.VerifyHS256([]byte(key), token, &claims))

					assert.NoError(b, claims.VerifyNotBefore(time.Now()))
					assert.NoError(b, claims.VerifyExpirationTime(time.Now()))
					assert.Equal(b, "jdoe@example.com", claims.Subject)
				}
			})

			b.Run("dgrijalva", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					t, err := jwt_dgrijalva.ParseWithClaims(tokenString, &jwt_dgrijalva.StandardClaims{}, func(token *jwt_dgrijalva.Token) (interface{}, error) {
						if token.Method.Alg() != jwt_dgrijalva.SigningMethodHS256.Name {
							return nil, jwt_dgrijalva.ErrInvalidKey
						}

						return []byte(key), nil
					})

					assert.NoError(b, err)
					assert.Equal(b, "jdoe@example.com", t.Claims.(*jwt_dgrijalva.StandardClaims).Subject)
				}
			})
		})
	})

	b.Run("rs256", func(b *testing.B) {
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
		assert.NoError(b, err)

		pemPublicKey := `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAlMhK8kfH33aII60/eOhk8Kic4FSmdmZ8Rp1M0zcGr9G5dXMlWf6F
P+mAhB1olpxeP7UyF9iG0pL8lD3NkXWnrCrwoh9rebI2JKbXMTTNXJazcJvBFcOD
L+ueEPUSLzJZw7CypJF2ak7O7iniDFRCxQt/y7uUpST40bINt1SqBZtLJkzlN6G8
CZufgADePdFcY7ONWUYcfEiAozpV5thu4PBW3ShX5ExE4Ni894zKZ25VSyB7gHO+
/fWmxkmAeu6oSzzlcN88qptmwzsW6RF+Cmf5zHqepSeEdU5ZVwlSX9hgBWIOQKzz
+pqdh0Yzp85BugBWLXLPEWgwwFou5aYiwQIDAQAB
-----END RSA PUBLIC KEY-----`

		pemBlock, _ = pem.Decode([]byte(pemPublicKey))
		publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
		assert.NoError(b, err)

		b.Run("sign", func(b *testing.B) {
			b.Run("ucarion", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					claims := jwt_ucarion.StandardClaims{
						Subject:        "jdoe@example.com",
						NotBefore:      time.Now().Add(-time.Hour).Unix(),
						ExpirationTime: time.Now().Add(time.Hour).Unix(),
					}

					_, err := jwt_ucarion.SignRS256(privateKey, claims)
					assert.NoError(b, err)
				}
			})

			b.Run("dgrijalva", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					claims := jwt_dgrijalva.StandardClaims{
						Subject:   "jdoe@example.com",
						NotBefore: time.Now().Add(-time.Hour).Unix(),
						ExpiresAt: time.Now().Add(time.Hour).Unix(),
					}

					token := jwt_dgrijalva.NewWithClaims(jwt_dgrijalva.SigningMethodRS256, claims)
					_, err := token.SignedString(privateKey)
					assert.NoError(b, err)
				}
			})
		})

		b.Run("verify", func(b *testing.B) {
			// First, generate the token we'll verify.
			token, err := jwt_ucarion.SignRS256(privateKey, jwt_ucarion.StandardClaims{
				Subject:        "jdoe@example.com",
				NotBefore:      time.Now().Add(-time.Hour).Unix(),
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
			})

			assert.NoError(b, err)

			// dgrijalva/jwt-go parses JWTs as strings, not []byte
			tokenString := string(token)

			b.Run("ucarion", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					var claims jwt_ucarion.StandardClaims
					assert.NoError(b, jwt_ucarion.VerifyRS256(publicKey, token, &claims))

					assert.NoError(b, claims.VerifyNotBefore(time.Now()))
					assert.NoError(b, claims.VerifyExpirationTime(time.Now()))
					assert.Equal(b, "jdoe@example.com", claims.Subject)
				}
			})

			b.Run("dgrijalva", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					t, err := jwt_dgrijalva.ParseWithClaims(tokenString, &jwt_dgrijalva.StandardClaims{}, func(token *jwt_dgrijalva.Token) (interface{}, error) {
						if token.Method.Alg() != jwt_dgrijalva.SigningMethodRS256.Name {
							return nil, jwt_dgrijalva.ErrInvalidKey
						}

						return publicKey, nil
					})

					assert.NoError(b, err)
					assert.Equal(b, "jdoe@example.com", t.Claims.(*jwt_dgrijalva.StandardClaims).Subject)
				}
			})
		})
	})

	b.Run("es256", func(b *testing.B) {
		pemPrivateKey := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINjhxbMoJfxovy0ivk1UAe0DAs+BFnL0NmzNabfTZq/FoAoGCCqGSM49
AwEHoUQDQgAEm3MpqIDa7nhiqKA2TaiijXLIaOX2+RA1gl4SPWnRYULdqJUhdrw0
UmRjl6SsX9iLp1UmC9xuFws6cUYrEkn2iQ==
-----END EC PRIVATE KEY-----`

		pemBlock, _ := pem.Decode([]byte(pemPrivateKey))
		privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		assert.NoError(b, err)

		pemPublicKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm3MpqIDa7nhiqKA2TaiijXLIaOX2
+RA1gl4SPWnRYULdqJUhdrw0UmRjl6SsX9iLp1UmC9xuFws6cUYrEkn2iQ==
-----END PUBLIC KEY-----`

		pemBlock, _ = pem.Decode([]byte(pemPublicKey))
		publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		assert.NoError(b, err)

		b.Run("sign", func(b *testing.B) {
			b.Run("ucarion", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					claims := jwt_ucarion.StandardClaims{
						Subject:        "jdoe@example.com",
						NotBefore:      time.Now().Add(-time.Hour).Unix(),
						ExpirationTime: time.Now().Add(time.Hour).Unix(),
					}

					_, err := jwt_ucarion.SignES256(privateKey, claims)
					assert.NoError(b, err)
				}
			})

			b.Run("dgrijalva", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					claims := jwt_dgrijalva.StandardClaims{
						Subject:   "jdoe@example.com",
						NotBefore: time.Now().Add(-time.Hour).Unix(),
						ExpiresAt: time.Now().Add(time.Hour).Unix(),
					}

					token := jwt_dgrijalva.NewWithClaims(jwt_dgrijalva.SigningMethodES256, claims)
					_, err := token.SignedString(privateKey)
					assert.NoError(b, err)
				}
			})
		})

		b.Run("verify", func(b *testing.B) {
			// First, generate the token we'll verify.
			token, err := jwt_ucarion.SignES256(privateKey, jwt_ucarion.StandardClaims{
				Subject:        "jdoe@example.com",
				NotBefore:      time.Now().Add(-time.Hour).Unix(),
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
			})

			assert.NoError(b, err)

			// dgrijalva/jwt-go parses JWTs as strings, not []byte
			tokenString := string(token)

			b.Run("ucarion", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					var claims jwt_ucarion.StandardClaims
					assert.NoError(b, jwt_ucarion.VerifyES256(publicKey.(*ecdsa.PublicKey), token, &claims))

					assert.NoError(b, claims.VerifyNotBefore(time.Now()))
					assert.NoError(b, claims.VerifyExpirationTime(time.Now()))
					assert.Equal(b, "jdoe@example.com", claims.Subject)
				}
			})

			b.Run("dgrijalva", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					t, err := jwt_dgrijalva.ParseWithClaims(tokenString, &jwt_dgrijalva.StandardClaims{}, func(token *jwt_dgrijalva.Token) (interface{}, error) {
						if token.Method.Alg() != jwt_dgrijalva.SigningMethodES256.Name {
							return nil, jwt_dgrijalva.ErrInvalidKey
						}

						return publicKey, nil
					})

					assert.NoError(b, err)
					assert.Equal(b, "jdoe@example.com", t.Claims.(*jwt_dgrijalva.StandardClaims).Subject)
				}
			})
		})
	})
}

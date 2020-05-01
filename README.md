# jwt [![docs](https://godoc.org/github.com/ucarion/jwt?status.svg)](https://pkg.go.dev/github.com/ucarion/jwt?tab=doc)

This package is a Golang implementation of JSON Web Tokens that helps you avoid
common security mistakes when using JWTs. It does this by giving you:

1. An extremely simple, straightforward interface for securely reading and
   generating JWTs.
2. Leaving out any support for features in JWT that are usually used by mistake,
   and which lead to security vulnerabilities.

This package exports the simplest possible interface for using JWTs in Golang:

```go
// This is how you generate a JWT:
claims := jwt.StandardClaims{Subject: "john.doe@example.com"}
token, err := jwt.SignHS256([]byte("my-jwt-secret"), claims)
```

```go
// This is how you verify a JWT:
var claims jwt.StandardClaims
err := jwt.VerifyHS256([]byte("my-jwt-secret"), token, &claims)
```

One of the biggest features of this package is all the features it *doesn't*
have. In particular:

1. **You can't parse a JWT without first authenticating it.**

   This package does not give you any way to parse a JWT without also validating
   its signature. It's very common for developers to accidentally build systems
   which make decisions based on data that they have not authenticated. If you
   use this package, you can't easily make this mistake.

1. **Absolutely no support for the `none` algorithm.**

   Lots of developers accidentally build systems which accept the `none`
   algorithm, leading to serious vulnerabilities. This package does not give you
   a way to read the contents of a token signed with `none`. Tokens with `none`
   are always considered to have an invalid signature.

1. **The `alg` header does not decide what algorithm gets used. *You* decide
   what algorithm gets used.**

   This package does not support letting JWTs decide which verification
   algorithm is used. When you use this package, you choose a different function
   (`VerifyHS256`, `VerifyRS256`, or `VerifyES256`) based on whether you want to
   use HS256, RS256, or ES256. If the token you're verifying doesn't have the
   expected algorithm in its header, it's considered invalid.

   Other packages make you do this sort of check by hand. For example, some
   packages make you supply a list of "acceptable" algorithms, or give you back
   the algorithm it ended up using, and you have to do the check yourself.

   Manual `alg`-checking is a security risk because it's easy to forget to do,
   and forgetting to check the algorithm will often lead to security
   vulnerabilities. This package circumvents those risks by not letting
   untrusted, unauthenticated JWTs decide what algorithm gets used: you, the
   developer, decide what algorithm gets used, and the JWT is invalid if it
   doesn't use the right algorithm.

## Example usage

This section goes over common use-cases that you can implement with this
package.

### Verifying whether a token is expired

```go
// See later examples for how you can get claims out of a JWT.
//
// For this example, we'll just hard-code the claims for a token that is expired
// for two different reasons: its ExpirationTime is in the past, and its
// NotBefore time is in the future.
claims := jwt.StandardClaims{
  Subject:        "john.doe@example.com"
  ExpirationTime: time.Now().Add(-1 * time.Second).Unix(),
  NotBefore:      time.Now().Add(1 * time.Second).Unix(),
}

if err := claims.VerifyExpirationTime(time.Now()); err != nil {
  fmt.Println("not valid anymore!", err)
}

// This is a separate method because most people don't use NotBefore.
if err := claims.VerifyNotBefore(time.Now()); err != nil {
  fmt.Println("not yet valid!", err)
}
```

### Using a custom claim type

```go
// All of the other examples in this README use jwt.StandardClaims, but you can
// use any claim type you like. It just needs to be compatible with
// encoding/json.

type MyCustomClaims struct {
  MyCoolClaim string `json:"my_cool_claim"`

  // If you want to "extend" the standard claims, then embed jwt.StandardClaims
  // in your custom claim type, like so:
  jwt.StandardClaims
}

var claims MyCustomClaims
err := jwt.VerifyHS256([]byte("my-jwt-secret"), token, &claims)

if err != nil {
  panic(err)
}

fmt.Println(claims.MyCoolClaim)

// You can continue to use the provided expiration-checking functions when you
// embed jwt.StandardClaims inside your struct.
fmt.Println(claims.StandardClaims.VerifyExpirationTime(time.Now()))
```

### Creating HS256-signed JWTs

```go
claims := jwt.StandardClaims{Subject: "john.doe@example.com"}
token, err := jwt.SignHS256([]byte("my-jwt-secret"), claims)
```

### Verifying + Parsing HS256-signed JWTs

```go
var claims jwt.StandardClaims
err := jwt.VerifyHS256([]byte("my-jwt-secret"), token, &claims)
```

### Creating RS256-signed JWTs

```go
// See the examples for SignRS256 for a complete example of how to parse a RSA
// private key from a PEM file.
var privateKey *rsa.PrivateKey

claims := jwt.StandardClaims{Subject: "john.doe@example.com"}
token, err := jwt.SignRS256(, claims)
```

### Verifying + Parsing RS256-signed JWTs

```go
// See the examples for VerifyRS256 for a complete example of how to parse a RSA
// public key from a PEM file.
var publicKey *rsa.PublicKey

var claims jwt.StandardClaims
err := jwt.VerifyRS256(publicKey, token, &claims)
```

### Creating ES256-signed JWTs

```go
// See the examples for SignES256 for a complete example of how to parse a ECDSA
// private key from a PEM file.
var privateKey *ecdsa.PrivateKey

claims := jwt.StandardClaims{Subject: "john.doe@example.com"}
token, err := jwt.SignES256(privateKey, claims)
```

### Verifying + Parsing ES256-signed JWTs

```go
// See the examples for VerifyES256 for a complete example of how to parse a
// ECDSA public key from a PEM file.
var publicKey *ecdsa.PublicKey

var claims jwt.StandardClaims
err := jwt.VerifyES256(publicKey, token, &claims)
```

## Performance

Do your own benchmarking if performance matters a lot to you, but you can expect
slightly better performance with this package over
[`github.com/dgrijalva/jwt-go`](https://github.com/dgrijalva/jwt-go).

### HS256

```text
go test -benchmem -bench "^BenchmarkJWT/hs256" ./...
```

```text
goos: darwin
goarch: amd64
pkg: github.com/ucarion/jwt
BenchmarkJWT/hs256/sign/ucarion-8         	  342206	      3481 ns/op	    1192 B/op	      14 allocs/op
BenchmarkJWT/hs256/sign/dgrijalva-8       	  195742	      5288 ns/op	    2664 B/op	      38 allocs/op
BenchmarkJWT/hs256/verify/ucarion-8       	  156759	      7297 ns/op	    2168 B/op	      32 allocs/op
BenchmarkJWT/hs256/verify/dgrijalva-8     	  127647	      7865 ns/op	    3720 B/op	      55 allocs/op
PASS
ok  	github.com/ucarion/jwt	5.672s
```

### RS256

```text
go test -benchmem -bench "^BenchmarkJWT/rs256" ./...
```

```text
goos: darwin
goarch: amd64
pkg: github.com/ucarion/jwt
BenchmarkJWT/rs256/sign/ucarion-8         	     844	   1391652 ns/op	   22630 B/op	      94 allocs/op
BenchmarkJWT/rs256/sign/dgrijalva-8       	     838	   1418973 ns/op	   24680 B/op	     117 allocs/op
BenchmarkJWT/rs256/verify/ucarion-8       	   17104	     70495 ns/op	    7171 B/op	      38 allocs/op
BenchmarkJWT/rs256/verify/dgrijalva-8     	   16432	     75944 ns/op	    9308 B/op	      60 allocs/op
PASS
ok  	github.com/ucarion/jwt	6.701s
```

### ES256

```text
go test -benchmem -bench "^BenchmarkJWT/es256" ./...
```

```text
goos: darwin
goarch: amd64
pkg: github.com/ucarion/jwt
BenchmarkJWT/es256/sign/ucarion-8         	   36021	     30409 ns/op	    3630 B/op	      44 allocs/op
BenchmarkJWT/es256/sign/dgrijalva-8       	   36921	     32709 ns/op	    5231 B/op	      69 allocs/op
BenchmarkJWT/es256/verify/ucarion-8       	   13533	     89521 ns/op	    2873 B/op	      46 allocs/op
BenchmarkJWT/es256/verify/dgrijalva-8     	   13586	     92457 ns/op	    4489 B/op	      68 allocs/op
PASS
ok  	github.com/ucarion/jwt	7.376s
```

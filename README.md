# jwt

This package is a Golang implementation of JSON Web Token that helps you avoid
common security mistakes when using JWT. It does this by giving you:

1. An extremely simple, straightforward interface for securely reading and
   generating JWTs.
2. Leaving out any support for features in JWT that are usually used by mistake,
   and which lead to security vulnerabilities.

This package exports the simplest possible interface for using JWTs in Golang:

```go
import "github.com/ucarion/jwt"

// This is how you generate a JWT:
claims := jwt.StandardClaims{Subject: "john.doe@example.com"}
token, err := jwt.SignHS256([]byte("my-jwt-secret"), claims)
```

```go
import "github.com/ucarion/jwt"

// This is how you generate a JWT:
//
// If the token isn't valid, err will be jwt.ErrInvalidSignature and claims will
// be untouched.
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

   This package not support letting JWTs decide which verification algorithm is
   used. When you use this package, you choose a different function
   (`VerifyHS256`, `VerifyRS256`, or `VerifyES256`) based on whether you want to
   use HS256, RS256, or ES256. If the token you're verifying doesn't have the
   expected algorithm in its header, it's considered invalid.

   Other packages make you do this sort of check by hand. For example, some
   packages make you supply a list of "acceptable" algorithms, or give you back
   the algorithm it ended up using, and you have to do the check yourself.

   Approaches like this are security risks because they're easy to forget to do,
   and forgetting to check the algorithm will lead to security vulnerabilities.
   This package circumvents those risks by not letting untrusted,
   unauthenticated JWTs decide what algorithm gets used: you, the developer,
   decide what algorithm gets used, and the JWT is invalid if it doesn't use the
   right algorithm.

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

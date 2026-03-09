# simpauth

Go HTTP user authentication library with cookie-based session storage.

## Features

- Simple API with minimal configuration
- Cookie-based session with HttpOnly (serialized with msgp for compact size)
- Multiple token sources: Header, Cookie, URL param
- Auto refresh when nearing expiration
- Context integration for user propagation
- Works with standard `net/http` and Fiber

## Install

```bash
go get github.com/liut/simpauth
```

## Usage

```go
import auth "github.com/liut/simpauth"

// Create authorizer
authorizer := auth.New(
    auth.WithCookie("_user", "/", "example.net"), // cookie name, path, domain
    auth.WithMaxAge(3600),                        // max age in seconds
    auth.WithRefresh(),                           // auto refresh
)

// Login
func login(w http.ResponseWriter, r *http.Request) {
    user := &auth.User{
        UID:  "user123",
        Name: "John",
    }
    user.Refresh()
    authorizer.Signin(user, w)
}

// Protected handler
func welcome(w http.ResponseWriter, r *http.Request) {
    user, ok := auth.UserFromContext(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", 401)
        return
    }
    fmt.Fprintf(w, "Welcome, %s", user.Name)
}

// Apply middleware
handler := authorizer.Middleware()(http.HandlerFunc(welcome))
```

## Token Sources

Checked in order:

1. `Authorization: Bearer <token>` header
2. Cookie
3. URL parameter `?token=<token>`

## Options

- `WithCookie(name, path, domain)` - Configure cookie
- `WithMaxAge(seconds)` - Session lifetime, default 3600s
- `WithRefresh()` - Auto refresh when nearing expiration
- `WithURI(redirectURL)` - Redirect URL when unauthorized

## Sign Out

```go
authorizer.Signout(w)
```

## Convert Custom User Types

Implement `IUser` interface and use `ToUser()`:

```go
type IUser interface {
    GetOID() string
    GetUID() string
    GetName() string
    GetAvatar() string
}

authUser := auth.ToUser(myUser)
```

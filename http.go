package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

// vars
var (
	CookieName   = "_user"
	CookiePath   = "/"
	CookieMaxAge = 3600
)

type ctxKey int

// consts
const (
	UserKey ctxKey = iota
)

// Option ...
type Option struct {
	uri     string
	refresh bool
}

// OptFunc ...
type OptFunc func(opt *Option)

// WithURI The option with redirect uri
func WithURI(uri string) OptFunc {
	return func(opt *Option) {
		opt.uri = uri
	}
}

// WithRefresh The option with auto refresh
func WithRefresh() OptFunc {
	return func(opt *Option) {
		opt.refresh = true
	}
}

// Middleware ...
func Middleware(opts ...OptFunc) func(next http.Handler) http.Handler {
	var option Option
	for _, fn := range opts {
		fn(&option)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			user, err := UserFromRequest(req)
			if err != nil {
				if option.uri != "" {
					http.Redirect(rw, req, option.uri, http.StatusFound)
				} else {
					http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				}
				return
			}
			if option.refresh && user.NeedRefresh() {
				user.Refresh()
				user.Signin(rw) // TODO: custom cookieName somethings
			}

			req = req.WithContext(context.WithValue(req.Context(), UserKey, user))
			next.ServeHTTP(rw, req)
		})
	}
}

// WithRedirect ... Deprecated by Middleware(WithURI(uri))
func WithRedirect(uri string) func(next http.Handler) http.Handler {
	return Middleware(WithURI(uri))
}

// WithUnauthorized ... Deprecated by Middleware()
func WithUnauthorized() func(next http.Handler) http.Handler {
	return Middleware()
}

// UserFromContext ...
func UserFromContext(ctx context.Context) (*User, bool) {
	if ctx == nil {
		return nil, false
	}
	if obj, ok := ctx.Value(UserKey).(*User); ok {
		return obj, true
	}
	return nil, false
}

// UserFromRequest get user from cookie
func UserFromRequest(r *http.Request) (user *User, err error) {
	var cookie *http.Cookie
	cookie, err = r.Cookie(CookieName)
	if err != nil {
		log.Printf("cookie %q ERR %s", CookieName, err)
		return
	}
	user = new(User)
	err = user.Decode(cookie.Value)
	if err != nil {
		log.Printf("decode user ERR %s", err)
		return
	}
	if user.IsExpired() {
		log.Printf("user %s is expired", user.UID)
		err = fmt.Errorf("user %s is expired", user.UID)
	}
	// log.Printf("got user %v", user)
	return
}

// Signin call Signin for login
func (user *User) Signin(w http.ResponseWriter) error {
	return Signin(user, w)
}

type encoder interface {
	Encode() (string, error)
}

// Signin write user encoded string into cookie
func Signin(user encoder, w http.ResponseWriter) error {
	value, err := user.Encode()
	if err != nil {
		log.Printf("encode user ERR: %s", err)
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		MaxAge:   CookieMaxAge,
		Path:     CookiePath,
		HttpOnly: true,
	})
	return nil
}

// Signout setcookie with empty
func Signout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     CookiePath,
		HttpOnly: true,
	})
}

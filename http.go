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

// WithRedirect ...
func WithRedirect(uri string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hf := func(w http.ResponseWriter, r *http.Request) {
			user, err := UserFromRequest(r)
			if err != nil {
				http.Redirect(w, r, uri, http.StatusFound)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserKey, user)))
		}
		return http.HandlerFunc(hf)
	}
}

// WithUnauthorized ...
func WithUnauthorized() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hf := func(w http.ResponseWriter, r *http.Request) {
			user, err := UserFromRequest(r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserKey, user)))
		}
		return http.HandlerFunc(hf)
	}
}

// UserFromContext ...
func UserFromContext(ctx context.Context) *User {
	if ctx == nil {
		return nil
	}
	if obj, ok := ctx.Value(UserKey).(*User); ok {
		return obj
	}
	return nil
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

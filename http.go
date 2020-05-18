package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// vars
var (
	CookieName   = "_user"
	CookiePath   = "/"
	CookieMaxAge = 3600
	ParamName    = "token"

	ErrNoTokenInRequest = errors.New("no token present in request")
)

type ctxKey int

// consts
const (
	UserKey ctxKey = iota
)

// Option ...
type Option struct {
	URI     string // redirect URI
	Refresh bool   // need Refresh
}

// OptFunc ...
type OptFunc func(opt *Option)

// WithURI The option with redirect uri
func WithURI(uri string) OptFunc {
	return func(opt *Option) {
		opt.URI = uri
	}
}

// WithRefresh The option with auto refresh
func WithRefresh() OptFunc {
	return func(opt *Option) {
		opt.Refresh = true
	}
}

// NewOption ...
func NewOption(opts ...OptFunc) *Option {
	var option Option
	for _, fn := range opts {
		fn(&option)
	}
	return &option
}

// Middleware ...
func Middleware(opts ...OptFunc) func(next http.Handler) http.Handler {
	option := NewOption(opts...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			user, err := UserFromRequest(req)
			if err != nil {
				if option.URI != "" {
					http.Redirect(rw, req, option.URI, http.StatusFound)
				} else {
					http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				}
				return
			}
			if option.Refresh && user.NeedRefresh() {
				user.Refresh()
				user.Signin(rw) // TODO: custom cookieName somethings
			}

			req = req.WithContext(ContextWithUser(req.Context(), user))
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

// ContextWithUser ...
func ContextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, UserKey, user)
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
	var token string
	token, err = TokenFromRequest(r)
	if err != nil {
		log.Print(err)
		return
	}
	user = new(User)
	err = user.Decode(token)
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

// TokenFromRequest get a token from request
func TokenFromRequest(req *http.Request) (s string, err error) {
	s = TokenFrom(req.Header, req)
	if len(s) == 0 {
		err = ErrNoTokenInRequest
	}
	return
}

// Getter ...
type Getter interface {
	Get(k string) string
}

// Cookier ...
type Cookier interface {
	Cookie(k string) (*http.Cookie, error)
}

// FormValuer ...
type FormValuer interface {
	FormValue(k string) string
}

type cookieser interface{ Cookies(k string) string }

// TokenFrom return token string
// valid interfaces: *http.Request, Request.Header, *fiber.Ctx
func TokenFrom(args ...interface{}) string {
	for _, arg := range args {
		if v, ok := arg.(Getter); ok { // request.Header, fiber.Ctx
			if ah := v.Get("Authorization"); len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
				return ah[7:]
			}
		}

		if v, ok := arg.(Cookier); ok { // request
			if ck, err := v.Cookie(CookieName); err == nil && ck.Value != "" {
				return ck.Value
			}
		}
		if v, ok := arg.(cookieser); ok { // fiber.Ctx
			if s := v.Cookies(CookieName); s != "" {
				return s
			}
		}
		if v, ok := arg.(FormValuer); ok { // request form, fiber.Ctx
			if s := v.FormValue(ParamName); s != "" {
				return s
			}
		}
	}
	return ""
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

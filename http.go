package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Authorizer ...
type Authorizer interface {
	Middleware() func(next http.Handler) http.Handler
	MiddlewareWordy(redir bool) func(next http.Handler) http.Handler
	UserFromRequest(r *http.Request) (user *User, err error)
	TokenFromRequest(r *http.Request) (s string, err error)
	TokenFrom(args ...any) string
	Cooking(value string) *http.Cookie
	Signin(user Encoder, w http.ResponseWriter) error
	Signout(w http.ResponseWriter)
	With(opts ...OptFunc)
}

// vars
var (
	ErrNoTokenInRequest = errors.New("no token present in request")

	dftOpt *option

	_ Authorizer = (*option)(nil)
)

func init() {
	dftOpt = &option{
		CookieName:   "_user",
		CookiePath:   "/",
		CookieMaxAge: 3600,
		ParamName:    "token",
	}
}

// option ...
type option struct {
	URI          string // redirect URI
	Refresh      bool   // need Refresh
	CookieName   string
	CookiePath   string
	CookieDomain string
	CookieMaxAge int
	ParamName    string
}

func (opt *option) setDefaults() {
	if len(opt.CookieName) == 0 {
		opt.CookieName = dftOpt.CookieName
	}
	if len(opt.CookiePath) == 0 {
		opt.CookiePath = dftOpt.CookiePath
	}
	if len(opt.ParamName) == 0 {
		opt.ParamName = dftOpt.ParamName
	}
}

func (opt *option) With(opts ...OptFunc) {
	for _, fn := range opts {
		fn(opt)
	}
}

// OptFunc ...
type OptFunc func(opt *option)

// WithURI The option with redirect uri
func WithURI(uri string) OptFunc {
	return func(opt *option) {
		if len(uri) > 0 {
			opt.URI = uri
		}
	}
}

// WithRefresh The option with auto refresh
func WithRefresh() OptFunc {
	return func(opt *option) {
		opt.Refresh = true
	}
}

// WithCookie set cookie 1-3 options: name, path, domain, see also http.Cookie
func WithCookie(name string, args ...string) OptFunc {
	return func(opt *option) {
		opt.CookieName = name
		n := len(args)
		if n > 0 {
			if len(args[0]) > 0 { // path
				opt.CookiePath = args[0]
			}

			if n > 1 {
				if len(args[1]) > 0 { // domain
					opt.CookieDomain = args[1]
				}
			}
		}
	}
}

// WithMaxAge set cookie max age: >= 0, default 3600, see also http.Cookie
func WithMaxAge(age int) OptFunc {
	return func(opt *option) {
		if age >= 0 {
			opt.CookieMaxAge = age
		}
	}
}

// NewOption ..., Deprecated: use New()
func NewOption(opts ...OptFunc) Authorizer {
	return New(opts...)
}

// New build option with args
func New(opts ...OptFunc) Authorizer {
	opt := new(option)
	opt.setDefaults()
	opt.With(opts...)
	return opt
}

// Default return default instance
func Default() Authorizer {
	return dftOpt
}

// Middleware ...
func Middleware(opts ...OptFunc) func(next http.Handler) http.Handler {
	if len(opts) == 0 {
		return Default().Middleware()
	}
	return New(opts...).Middleware()
}

// Middleware ...
func (opt *option) Middleware() func(next http.Handler) http.Handler {
	return opt.MiddlewareWordy(false)
}

// MiddlewareWordy ...
func (opt *option) MiddlewareWordy(redir bool) func(next http.Handler) http.Handler {
	if opt == nil {
		opt = dftOpt
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			user, err := opt.UserFromRequest(req)
			if err != nil {
				if redir && opt.URI != "" {
					http.Redirect(rw, req, opt.URI, http.StatusFound)
				} else {
					http.Error(rw, err.Error(), http.StatusUnauthorized)
				}
				return
			}
			if opt.Refresh && user.NeedRefresh() {
				user.Refresh()
				_ = opt.Signin(user, rw)
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

// UserFromRequest get user from cookie, Deprecated
func UserFromRequest(r *http.Request) (user *User, err error) {
	return dftOpt.UserFromRequest(r)
}

// UserFromRequest get user from cookie
func (opt *option) UserFromRequest(r *http.Request) (user *User, err error) {
	var token string
	token, err = opt.TokenFromRequest(r)
	if err != nil {
		slog.Info("no token in req", "cn", opt.CookieName, "err", err)
		return
	}
	user = new(User)
	err = user.Decode(token)
	if err != nil {
		slog.Info("decode fail", "token", token, "err", err)
		return
	}
	if user.IsExpired() {
		slog.Info("expired", "token", token, "uid", user.UID)
		err = fmt.Errorf("user %s is expired", user.UID)
	}
	// slog.Debug("got usr from req", "user", user)
	return
}

// TokenFromRequest get a token from request
func (opt *option) TokenFromRequest(req *http.Request) (s string, err error) {
	s = opt.TokenFrom(req.Header, req)
	if len(s) == 0 {
		err = ErrNoTokenInRequest
	}
	return
}

// Getter ex: Request.Header
type Getter interface {
	Get(k string) string
}

// Cookier ex: http.Request
type Cookier interface {
	Cookie(k string) (*http.Cookie, error)
}

// FormValuer ex: http.Request
type FormValuer interface {
	FormValue(k string) string
}

// ex: fiber.Ctx
type cookieser interface{ Cookies(k string) string }

// TokenFrom return token string
// valid interfaces: *http.Request, Request.Header, *fiber.Ctx
func TokenFrom(args ...any) string {
	return New().TokenFrom(args...)
}

// TokenFrom return token string
// valid interfaces: *http.Request, Request.Header, *fiber.Ctx
func (opt *option) TokenFrom(args ...any) string {
	for _, arg := range args {
		if v, ok := arg.(Getter); ok { // request.Header, fiber.Ctx
			if ah := v.Get("Authorization"); len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
				return ah[7:]
			}
		}

		if v, ok := arg.(Cookier); ok { // request
			if ck, err := v.Cookie(opt.CookieName); err == nil && ck.Value != "" {
				return ck.Value
			}
		}
		if v, ok := arg.(cookieser); ok { // fiber.Ctx
			if s := v.Cookies(opt.CookieName); s != "" {
				return s
			}
		}
		if v, ok := arg.(FormValuer); ok { // request form, fiber.Ctx
			if s := v.FormValue(opt.ParamName); s != "" {
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

// Encoder ...
type Encoder interface {
	Encode() (string, error)
}

// Signin write user encoded string into cookie, Deprecated
func Signin(user Encoder, w http.ResponseWriter) error {
	return dftOpt.Signin(user, w)
}

// Signin write user encoded string into cookie
func (opt *option) Signin(user Encoder, w http.ResponseWriter) error {
	value, err := user.Encode()
	if err != nil {
		slog.Info("encode fail", "err", err)
		return err
	}
	http.SetCookie(w, opt.Cooking(value))
	return nil
}

// Cooking ...
func (opt *option) Cooking(value string) *http.Cookie {
	return &http.Cookie{
		Name:     opt.CookieName,
		Value:    value,
		MaxAge:   opt.CookieMaxAge,
		Path:     opt.CookiePath,
		HttpOnly: true,
	}
}

// Signout setcookie with empty, Deprecated
func Signout(w http.ResponseWriter) {
	dftOpt.Signout(w)
}

// Signout setcookie with empty
func (opt *option) Signout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     opt.CookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     opt.CookiePath,
		HttpOnly: true,
	})
}

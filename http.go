package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Authorizer ...
type Authorizer interface {
	Middleware() func(next http.Handler) http.Handler
	UserFromRequest(r *http.Request) (user *User, err error)
	TokenFromRequest(r *http.Request) (s string, err error)
	TokenFrom(args ...interface{}) string
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
	if opt == nil {
		opt = new(option)
	}
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
	opt.setDefaults()
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
func WithCookie(strs ...string) OptFunc {
	return func(opt *option) {
		n := len(strs)
		if n > 0 {
			if len(strs[0]) > 0 {
				opt.CookieName = strs[0]
			}

			if n > 1 {
				if len(strs[1]) > 0 {
					opt.CookiePath = strs[1]
				}

				if n > 2 {
					if len(strs[2]) > 0 {
						opt.CookieDomain = strs[2]
					}

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

// NewOption ...
func NewOption(opts ...OptFunc) Authorizer {
	return New(opts...)
}

// New build option with args
func New(opts ...OptFunc) Authorizer {
	if len(opts) == 0 {
		return dftOpt
	}
	option := new(option)
	option.With(opts...)
	return option
}

// Middleware ...
func Middleware(opts ...OptFunc) func(next http.Handler) http.Handler {
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
					http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				}
				return
			}
			if opt.Refresh && user.NeedRefresh() {
				user.Refresh()
				opt.Signin(user, rw)
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

// UserFromRequest get user from cookie, deprecated
func UserFromRequest(r *http.Request) (user *User, err error) {
	return dftOpt.UserFromRequest(r)
}

// UserFromRequest get user from cookie
func (opt *option) UserFromRequest(r *http.Request) (user *User, err error) {
	if opt == nil {
		opt = dftOpt
	}
	var token string
	token, err = opt.TokenFromRequest(r)
	if err != nil {
		log.Printf("%s, cookie %s", err, opt.CookieName)
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
func (opt *option) TokenFromRequest(req *http.Request) (s string, err error) {
	if opt == nil {
		opt = dftOpt
	}
	s = opt.TokenFrom(req.Header, req)
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
	return New().TokenFrom(args...)
}

// TokenFrom return token string
// valid interfaces: *http.Request, Request.Header, *fiber.Ctx
func (opt *option) TokenFrom(args ...interface{}) string {
	if opt == nil {
		opt = dftOpt
	}
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

// Signin write user encoded string into cookie, deprecated
func Signin(user Encoder, w http.ResponseWriter) error {
	return dftOpt.Signin(user, w)
}

// Signin write user encoded string into cookie
func (opt *option) Signin(user Encoder, w http.ResponseWriter) error {
	if opt == nil {
		opt = dftOpt
	}
	value, err := user.Encode()
	if err != nil {
		log.Printf("encode user ERR: %s", err)
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

// Signout setcookie with empty, deprecated
func Signout(w http.ResponseWriter) {
	dftOpt.Signout(w)
}

// Signout setcookie with empty
func (opt *option) Signout(w http.ResponseWriter) {
	if opt == nil {
		opt = dftOpt
	}
	http.SetCookie(w, &http.Cookie{
		Name:     opt.CookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     opt.CookiePath,
		HttpOnly: true,
	})
}

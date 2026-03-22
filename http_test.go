package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPSignin(t *testing.T) {
	opt := New()
	opt.With(WithURI("/"), WithRefresh())
	user := &User{
		UID:  "testUID",
		Name: "testName",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user.Refresh()
		err := opt.Signin(user, w)
		assert.Nil(t, err)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusAccepted, res.StatusCode)
}

func TestHTTPBack(t *testing.T) {
	opt := New(
		WithCookie("myname", "/", "localhost"),
		WithMaxAge(1800),
		WithRefresh(),
	)
	user := &User{
		UID:  "testUID",
		Name: "testName",
	}
	user.LastHit = time.Now().Unix() - DefaultLifetime + 10
	token, err := user.Encode()
	assert.Nil(t, err)

	mw := opt.Middleware()
	ts := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, user.UID, u.UID)
		opt.Signout(w)
	})))
	defer ts.Close()

	t.Run("unauthorized", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL, nil)
		res, err := ts.Client().Do(req)
		assert.Nil(t, err)
		assert.Equal(t, 401, res.StatusCode)
	})

	t.Run("from_header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := ts.Client().Do(req)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("from_cookie", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL, nil)
		req.AddCookie(opt.Cooking(token))
		res, err := ts.Client().Do(req)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})

	t.Run("from_param", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/?"+dftOpt.ParamName+"="+token, nil)
		res, err := ts.Client().Do(req)
		assert.Nil(t, err)
		assert.Equal(t, 200, res.StatusCode)
	})
}

func TestNewOption(t *testing.T) {
	opt := New()
	assert.NotNil(t, opt)

	o := opt.(*option)
	assert.Equal(t, dftOpt.CookieName, o.CookieName)
	assert.Equal(t, dftOpt.ParamName, o.ParamName)
}

func TestDefaultInstance(t *testing.T) {
	def := Default()
	assert.NotNil(t, def)
	assert.Equal(t, dftOpt, def)
}

func TestOptionWith(t *testing.T) {
	opt := New(
		WithURI("/login"),
		WithRefresh(),
		WithCookie("custom", "/", "example.com"),
		WithMaxAge(7200),
		WithHeader("X-Custom-Token"),
	)
	o := opt.(*option)

	assert.Equal(t, "/login", o.URI)
	assert.True(t, o.Refresh)
	assert.Equal(t, "custom", o.CookieName)
	assert.Equal(t, "/", o.CookiePath)
	assert.Equal(t, "example.com", o.CookieDomain)
	assert.Equal(t, 7200, o.CookieMaxAge)
	assert.Equal(t, "X-Custom-Token", o.HeaderKey)
}

func TestWithURI(t *testing.T) {
	opt := New(WithURI(""))
	o := opt.(*option)
	assert.Empty(t, o.URI)

	opt = New(WithURI("/dashboard"))
	o = opt.(*option)
	assert.Equal(t, "/dashboard", o.URI)
}

func TestWithMaxAge(t *testing.T) {
	opt := New(WithMaxAge(0))
	o := opt.(*option)
	assert.Equal(t, 0, o.CookieMaxAge)

	opt = New(WithMaxAge(-1))
	o = opt.(*option)
	assert.Equal(t, 0, o.CookieMaxAge) // negative should be ignored
}

func TestOptionSignout(t *testing.T) {
	opt := New(WithCookie("testcookie"))
	w := httptest.NewRecorder()
	opt.Signout(w)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "testcookie", cookies[0].Name)
	assert.Empty(t, cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestCooking(t *testing.T) {
	opt := New(WithCookie("mycookie", "/path", "domain.com"), WithMaxAge(1800))
	ck := opt.Cooking("tokenvalue")

	assert.Equal(t, "mycookie", ck.Name)
	assert.Equal(t, "tokenvalue", ck.Value)
	assert.Equal(t, "/path", ck.Path)
	assert.Equal(t, "domain.com", ck.Domain)
	assert.Equal(t, 1800, ck.MaxAge)
	assert.True(t, ck.HttpOnly)
}

func TestTokenFromHeader(t *testing.T) {
	opt := New()

	token := opt.TokenFrom(http.Header{"Authorization": {"Bearer testtoken"}})
	assert.Equal(t, "testtoken", token)

	opt2 := New(WithHeader("X-My-Token"))
	token = opt2.TokenFrom(http.Header{"X-My-Token": {"customheadertoken"}})
	assert.Equal(t, "customheadertoken", token)
}

func TestTokenFromCookie(t *testing.T) {
	opt := New(WithCookie("session"))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "cookietoken"})

	token := opt.TokenFrom(req)
	assert.Equal(t, "cookietoken", token)
}

func TestTokenFromForm(t *testing.T) {
	opt := New()
	req := httptest.NewRequest("POST", "/?token=formtoken", nil)

	token := opt.TokenFrom(req)
	assert.Equal(t, "formtoken", token)
}

func TestTokenFromNoToken(t *testing.T) {
	opt := New()
	req := httptest.NewRequest("GET", "/", nil)

	token := opt.TokenFrom(req)
	assert.Empty(t, token)
}

// mockGetter implements Getter interface
type mockGetter struct {
	data map[string]string
}

func (m *mockGetter) Get(k string) string {
	return m.data[k]
}

// mockCookier implements Cookier interface
type mockCookier struct {
	cookies map[string]*http.Cookie
}

func (m *mockCookier) Cookie(k string) (*http.Cookie, error) {
	ck, ok := m.cookies[k]
	if !ok {
		return nil, http.ErrNoCookie
	}
	return ck, nil
}

// mockCookieser implements cookieser interface (fiber.Ctx)
type mockCookieser struct {
	data map[string]string
}

func (m *mockCookieser) Cookies(k string) string {
	return m.data[k]
}

// mockFormValuer implements FormValuer interface
type mockFormValuer struct {
	data map[string]string
}

func (m *mockFormValuer) FormValue(k string) string {
	return m.data[k]
}

func TestTokenFromGetterNoBearer(t *testing.T) {
	opt := New()
	// Test Getter with non-Bearer Authorization header
	getter := &mockGetter{
		data: map[string]string{
			"Authorization": "Basic dXNlcjpwYXNz", // Basic auth, not Bearer
			"token":         "fromtoken",
		},
	}

	token := opt.TokenFrom(getter)
	assert.Equal(t, "fromtoken", token) // Should fall through to HeaderKey
}

func TestTokenFromGetterEmptyAuthorization(t *testing.T) {
	opt := New()
	// Test Getter with empty Authorization
	getter := &mockGetter{
		data: map[string]string{
			"Authorization": "",
			"token":         "tokenvalue",
		},
	}

	token := opt.TokenFrom(getter)
	assert.Equal(t, "tokenvalue", token)
}

func TestTokenFromCookierError(t *testing.T) {
	opt := New()
	// Cookier with non-existent cookie (error path)
	cookier := &mockCookier{
		cookies: map[string]*http.Cookie{},
	}

	token := opt.TokenFrom(cookier)
	assert.Empty(t, token)
}

func TestTokenFromCookierEmptyValue(t *testing.T) {
	opt := New()
	// Cookier with empty cookie value
	cookier := &mockCookier{
		cookies: map[string]*http.Cookie{
			"session": {Name: "session", Value: ""},
		},
	}

	token := opt.TokenFrom(cookier)
	assert.Empty(t, token)
}

func TestTokenFromCookieser(t *testing.T) {
	opt := New(WithCookie("session"))
	// Test cookieser interface (fiber.Ctx mock)
	cookieser := &mockCookieser{
		data: map[string]string{
			"session": "fibercookievalue",
		},
	}

	token := opt.TokenFrom(cookieser)
	assert.Equal(t, "fibercookievalue", token)
}

func TestTokenFromFormValuer(t *testing.T) {
	opt := New()
	// Test FormValuer interface (uses default ParamName "token")
	form := &mockFormValuer{
		data: map[string]string{
			"token": "formvalue",
		},
	}

	token := opt.TokenFrom(form)
	assert.Equal(t, "formvalue", token)
}

func TestTokenFromAllInterfaces(t *testing.T) {
	opt := New(
		WithCookie("session"),
		WithHeader("X-Token"),
	)

	// First match should win - test Getter Bearer
	getter := &mockGetter{
		data: map[string]string{
			"Authorization": "Bearer firsttoken",
			"X-Token":       "headertoken",
		},
	}
	token := opt.TokenFrom(getter)
	assert.Equal(t, "firsttoken", token)

	// Test that Getter Bearer is checked before HeaderKey
	getter2 := &mockGetter{
		data: map[string]string{
			"Authorization": "Bearer beartoken",
			"X-Token":       "headertoken",
		},
	}
	token = opt.TokenFrom(getter2)
	assert.Equal(t, "beartoken", token)
}

func TestUserFromRequestNoToken(t *testing.T) {
	opt := New()
	req := httptest.NewRequest("GET", "/", nil)

	_, err := opt.UserFromRequest(req)
	assert.Equal(t, ErrNoTokenInRequest, err)
}

func TestUserFromRequestExpired(t *testing.T) {
	opt := New()
	user := &User{
		UID:     "test",
		Name:    "Test",
		LastHit: time.Now().Unix() - DefaultLifetime - 100,
	}
	token, err := user.Encode()
	assert.Nil(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = opt.UserFromRequest(req)
	assert.NotNil(t, err)
}

func TestUserFromRequestValid(t *testing.T) {
	opt := New()
	user := &User{
		UID:     "uid123",
		Name:    "TestUser",
		LastHit: time.Now().Unix(),
	}
	token, err := user.Encode()
	assert.Nil(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	u, err := opt.UserFromRequest(req)
	assert.Nil(t, err)
	assert.Equal(t, user.UID, u.UID)
	assert.Equal(t, user.Name, u.Name)
}

func TestMiddlewareRedirect(t *testing.T) {
	opt := New(WithURI("/login"))
	mw := opt.MiddlewareWordy(true)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestMiddlewareNoRedirect(t *testing.T) {
	opt := New(WithURI("/login"))
	mw := opt.MiddlewareWordy(false)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddlewareNilOption(t *testing.T) {
	var opt *option
	mw := opt.MiddlewareWordy(false)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddlewareWithRefresh(t *testing.T) {
	opt := New(WithRefresh())
	user := &User{
		UID:     "test",
		Name:    "Test",
		LastHit: time.Now().Unix() - DefaultLifetime + 10,
	}
	token, err := user.Encode()
	assert.Nil(t, err)

	mw := opt.MiddlewareWordy(false)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, user.UID, u.UID)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
}

func TestMiddlewareContextWithUser(t *testing.T) {
	opt := New()
	user := &User{
		UID:     "contextuser",
		Name:    "Context",
		LastHit: time.Now().Unix(),
	}
	token, err := user.Encode()
	assert.Nil(t, err)

	var gotUser *User
	mw := opt.Middleware()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		gotUser, ok = UserFromContext(r.Context())
		assert.True(t, ok)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, user.UID, gotUser.UID)
}

func TestContextWithUserNil(t *testing.T) {
	u, ok := UserFromContext(nil)
	assert.Nil(t, u)
	assert.False(t, ok)
}

func TestTokenFromRequest(t *testing.T) {
	opt := New()
	req := httptest.NewRequest("GET", "/", nil)

	_, err := opt.TokenFromRequest(req)
	assert.Equal(t, ErrNoTokenInRequest, err)
}

func TestGlobalUserFromRequest(t *testing.T) {
	user := &User{
		UID:     "global",
		Name:    "Global",
		LastHit: time.Now().Unix(),
	}
	token, err := user.Encode()
	assert.Nil(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	got, err := UserFromRequest(req)
	assert.Nil(t, err)
	assert.Equal(t, user.UID, got.UID)
}

func TestDefaultSignin(t *testing.T) {
	user := &User{
		UID:  "default",
		Name: "Default",
	}

	w := httptest.NewRecorder()
	err := Signin(user, w)
	assert.Nil(t, err)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, dftOpt.CookieName, cookies[0].Name)
}

func TestDefaultSignout(t *testing.T) {
	w := httptest.NewRecorder()
	Signout(w)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestGlobalMiddleware(t *testing.T) {
	mw := Middleware()
	assert.NotNil(t, mw)

	mw = Middleware(WithCookie("test"))
	assert.NotNil(t, mw)
}

func TestGlobalTokenFrom(t *testing.T) {
	token := TokenFrom(http.Header{"Token": {"global"}})
	assert.Equal(t, "global", token)

	token = TokenFrom()
	assert.Empty(t, token)
}

func TestOptionSetDefaults(t *testing.T) {
	opt := &option{}
	opt.setDefaults()

	assert.Equal(t, dftOpt.CookieName, opt.CookieName)
	assert.Equal(t, dftOpt.CookiePath, opt.CookiePath)
	assert.Equal(t, dftOpt.ParamName, opt.ParamName)
}

func TestOptionSetDefaultsPreserveNonEmpty(t *testing.T) {
	opt := &option{
		CookieName: "preserve",
		CookiePath: "/custom",
		ParamName:  "customparam",
	}
	opt.setDefaults()

	assert.Equal(t, "preserve", opt.CookieName)
	assert.Equal(t, "/custom", opt.CookiePath)
	assert.Equal(t, "customparam", opt.ParamName)
}

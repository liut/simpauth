package auth

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockUser implements IUser for testing
type mockUser struct {
	oid    string
	uid    string
	name   string
	avatar string
}

func (m mockUser) GetOID() string    { return m.oid }
func (m mockUser) GetUID() string    { return m.uid }
func (m mockUser) GetName() string   { return m.name }
func (m mockUser) GetAvatar() string { return m.avatar }

func TestToUser(t *testing.T) {
	m := mockUser{
		oid:    "oid123",
		uid:    "user001",
		avatar: "https://example.com/avatar.png",
		name:   "Test User",
	}

	u := ToUser(m)

	assert.Equal(t, m.oid, u.OID)
	assert.Equal(t, m.uid, u.UID)
	assert.Equal(t, m.name, u.Name)
	assert.Equal(t, m.avatar, u.Avatar)
}

func TestUserIsExpired(t *testing.T) {
	// Not expired - future timestamp
	future := time.Now().Unix() + 3600
	u := &User{LastHit: future}
	assert.False(t, u.IsExpired())

	// Expired - past timestamp
	past := time.Now().Unix() - 7200
	u = &User{LastHit: past}
	assert.True(t, u.IsExpired())

	// Zero lifetime - never expired
	original := DefaultLifetime
	DefaultLifetime = 0
	defer func() { DefaultLifetime = original }()
	u = &User{LastHit: time.Now().Unix() - 7200}
	assert.False(t, u.IsExpired())
}

func TestUserNeedRefresh(t *testing.T) {
	now := time.Now().Unix()

	// Within refresh window (Lifetime/2 ~ Lifetime)
	DefaultLifetime = 3600
	u := &User{LastHit: now - 2000} // 2000 > 1800 (Lifetime/2) && 2000 < 3600
	assert.True(t, u.NeedRefresh())

	// Already expired
	u = &User{LastHit: now - 4000}
	assert.False(t, u.NeedRefresh())

	// Too recent to refresh
	u = &User{LastHit: now - 500}
	assert.False(t, u.NeedRefresh())
}

func TestUserDecode(t *testing.T) {
	// Test with valid token
	u := &User{UID: "test", Name: "testname"}
	token, err := u.Encode()
	assert.Nil(t, err)

	var decoded User
	err = decoded.Decode(token)
	assert.Nil(t, err)
	assert.Equal(t, u.UID, decoded.UID)
	assert.Equal(t, u.Name, decoded.Name)

	// Test with invalid token
	var invalid User
	err = invalid.Decode("invalid-token!!!")
	assert.NotNil(t, err)
}

func TestDefault(t *testing.T) {
	d := Default()
	assert.NotNil(t, d)
}

func TestMiddleware(t *testing.T) {
	// Test Middleware with default options
	mw := Middleware()
	assert.NotNil(t, mw)

	// Test Middleware with custom options
	mw = Middleware(WithURI("/login"), WithRefresh())
	assert.NotNil(t, mw)
}

func TestWithRedirect(t *testing.T) {
	// Test deprecated WithRedirect function
	mw := WithRedirect("/login")
	assert.NotNil(t, mw)
}

func TestTokenFrom(t *testing.T) {
	// Test package-level TokenFrom
	// With empty args should return empty
	s := TokenFrom()
	assert.Empty(t, s)
}

func TestSignin(t *testing.T) {
	// Test package-level Signin
	u := &User{UID: "test", Name: "test"}
	w := httptest.NewRecorder()

	err := Signin(u, w)
	assert.Nil(t, err)
	assert.Contains(t, w.Header().Get("Set-Cookie"), "_user=")
}

func TestSignout(t *testing.T) {
	// Test package-level Signout
	w := httptest.NewRecorder()
	Signout(w)
	assert.Contains(t, w.Header().Get("Set-Cookie"), "Max-Age=0")
}

func TestUserFromRequest(t *testing.T) {
	// Test package-level UserFromRequest with no token
	req := httptest.NewRequest("GET", "/", nil)
	_, err := UserFromRequest(req)
	assert.NotNil(t, err)
}

// testEncoder implements Encoder for testing
type testEncoder struct {
	uid  string
	name string
	err  error
}

func (e testEncoder) Encode() (string, error) {
	if e.err != nil {
		return "", e.err
	}
	u := &User{UID: e.uid, Name: e.name}
	return u.Encode()
}

func TestSigninWithEncoderError(t *testing.T) {
	opt := New()
	w := httptest.NewRecorder()
	e := testEncoder{err: assert.AnError}

	err := opt.Signin(e, w)
	assert.Equal(t, assert.AnError, err)
}

func TestUserFromContextNil(t *testing.T) {
	// Test with TODO context
	u, ok := UserFromContext(context.TODO())
	assert.Nil(t, u)
	assert.False(t, ok)

	// Test with context without user
	ctx := context.Background()
	u, ok = UserFromContext(ctx)
	assert.Nil(t, u)
	assert.False(t, ok)
}

func TestUserFromContextWithUser(t *testing.T) {
	u := &User{UID: "test", Name: "test"}
	ctx := ContextWithUser(context.Background(), u)

	got, ok := UserFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, u.UID, got.UID)
}

func TestToUserEmpty(t *testing.T) {
	// Test with empty mock
	m := mockUser{}
	u := ToUser(m)

	assert.Empty(t, u.OID)
	assert.Empty(t, u.UID)
	assert.Empty(t, u.Name)
	assert.Empty(t, u.Avatar)
}

func TestUserGetUID(t *testing.T) {
	u := &User{UID: "test-uid"}
	assert.Equal(t, "test-uid", u.GetUID())
}

func TestUserGetName(t *testing.T) {
	u := &User{Name: "test-name"}
	assert.Equal(t, "test-name", u.GetName())
}

func TestUserSignin(t *testing.T) {
	// Test User.Signin method (calls package-level Signin)
	u := &User{UID: "test", Name: "test"}
	w := httptest.NewRecorder()

	err := u.Signin(w)
	assert.Nil(t, err)
	assert.Contains(t, w.Header().Get("Set-Cookie"), "_user=")
}

func TestNamesHas(t *testing.T) {
	names := Names{"admin", "member", "editor"}

	assert.True(t, names.Has("admin"))
	assert.True(t, names.Has("member"))
	assert.True(t, names.Has("editor"))
	assert.False(t, names.Has("guest"))
	assert.False(t, names.Has(""))
}

func TestNamesHasEmpty(t *testing.T) {
	var names Names
	assert.False(t, names.Has("admin"))
}

package auth

import (
	"encoding/base64"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// IUser ...
type IUser interface {
	GetOID() string
	GetUID() string  // uid
	GetName() string // nickname
	GetAvatar() string
}

func ToUser(u IUser) User {
	return User{
		OID:    u.GetOID(),
		UID:    u.GetUID(),
		Name:   u.GetName(),
		Avatar: u.GetAvatar(),
	}
}

//go:generate msgp -io=false

// vars
var (
	DefaultLifetime int64 = 3600
	Guest                 = &User{}
)

// Names ...
type Names []string

// Has ...
func (z Names) Has(name string) bool {
	return slices.Contains(z, name)
}

// User 在线用户
type User struct {
	OID       string `json:"oid,omitzero" msg:"i"` // pk id, objectID, see define in andvari
	UID       string `json:"uid" msg:"u"`          // username, login name
	Name      string `json:"name" msg:"n"`         // nickname, realname, display name
	Avatar    string `json:"avatar,omitzero" msg:"a"`
	LastHit   int64  `json:"hit,omitzero" msg:"h"`
	TeamID    int64  `json:"tid,omitzero" msg:"t"`
	Roles     Names  `json:"roles,omitzero" msg:"r"`
	Watchings Names  `json:"watching,omitzero" msg:"w"`
}

func (u User) GetUID() string {
	return u.UID
}

func (u User) GetName() string {
	return u.Name
}

// IsExpired ...
func (u *User) IsExpired() bool {
	return u.IsExpiredWith(DefaultLifetime)
}

// IsExpiredWith checks if the user is expired with given lifetime in seconds.
func (u *User) IsExpiredWith(lifetime int64) bool {
	if lifetime <= 0 {
		return false
	}
	return u.LastHit+int64(lifetime) < time.Now().Unix()
}

// NeedRefresh checks if the user needs refresh.
func (u *User) NeedRefresh() bool {
	return u.NeedRefreshWith(DefaultLifetime)
}

// NeedRefreshWith checks if the user needs refresh with given lifetime in seconds.
func (u *User) NeedRefreshWith(lifetime int64) bool {
	gash := time.Now().Unix() - u.LastHit
	if lifetime == 0 || gash > lifetime {
		return false
	}

	return gash < lifetime && gash > lifetime/2
}

// Refresh lastHit to time Unix
func (u *User) Refresh() {
	u.LastHit = time.Now().Unix()
}

// Encode ...
func (u User) Encode() (s string, err error) {
	var b []byte
	b, err = u.MarshalMsg(nil)
	if err == nil {
		s = strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	}
	return
}

// Decode ...
func (u *User) Decode(s string) (err error) {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}

	var b []byte
	b, err = base64.URLEncoding.DecodeString(s)
	if err != nil {
		slog.Info("decode token fail", "s", s)
		return
	}

	*u = User{}
	_, err = u.UnmarshalMsg(b)
	if err != nil {
		slog.Info("unmarshal msg fail", "b", len(b), "s", s, "err", err)
	}

	return
}

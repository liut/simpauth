package auth

import (
	"encoding/base64"
	"log"
	"strings"
	"time"
)

//go:generate msgp -io=false

// vars
var (
	UserLifetime int64 = 3600
	Guest              = &User{}
)

// Names ...
type Names []string

// Has ...
func (z Names) Has(name string) bool {
	for _, item := range z {
		if item == name {
			return true
		}
	}
	return false
}

// User 在线用户
type User struct {
	UID       string `json:"uid" msg:"u"`
	Name      string `json:"name" msg:"n"`
	Avatar    string `json:"avatar,omitempty" msg:"a"`
	LastHit   int64  `json:"hit,omitempty" msg:"h"`
	TeamID    int64  `json:"tid,omitempty" msg:"t"`
	Roles     Names  `json:"roles,omitempty" msg:"r"`
	Watchings Names  `json:"watching,omitempty" msg:"w"`
}

func (u User) GetUID() string {
	return u.UID
}

func (u User) GetName() string {
	return u.Name
}

// IsExpired ...
func (u *User) IsExpired() bool {
	if UserLifetime <= 0 {
		return false
	}
	return u.LastHit+int64(UserLifetime) < time.Now().Unix()
}

// NeedRefresh ...
func (u *User) NeedRefresh() bool {
	gash := time.Now().Unix() - u.LastHit
	if UserLifetime == 0 || gash > UserLifetime { // expired
		return false
	}

	return gash < UserLifetime && gash > UserLifetime/2
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
		log.Printf("decode token %q ERR %s", s, err)
		return
	}

	*u = User{}
	_, err = u.UnmarshalMsg(b)
	if err != nil {
		log.Printf("unmarshal(%d) to msgpack from %q ERR %s", len(b), s, err)
	}

	return
}

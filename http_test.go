package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPSignin(t *testing.T) {
	var user = &User{
		UID:  "testUID",
		Name: "testName",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user.Refresh()
		user.Signin(w)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("get fail %s", err)
	}
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("invalid status %d", res.StatusCode)
	}
	t.Logf("res status %d", res.StatusCode)
	// t.Logf("res header %v", res.Header)
	// t.Logf("res cookies %v", res.Cookies())

}

type vector struct {
	name string
	req  *http.Request
	want int
}

func TestHTTPBack(t *testing.T) {
	var user = &User{
		UID:  "testUID",
		Name: "testName",
	}
	// user.Refresh()
	user.LastHit = time.Now().Unix() - UserLifetime + 10
	token, err := user.Encode()
	if err != nil {
		t.Fatalf("encode fail %s", err)
	}
	t.Logf("refresh: %d, token: %s", user.LastHit, token)

	mw := Middleware(WithRefresh())
	ts := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			t.Fatal("userFromContext fail")
		}
		t.Logf("user %v", user)
	})))

	defer ts.Close()
	t.Logf("test url %s", ts.URL)

	var req *http.Request
	var vectors []vector
	req, _ = http.NewRequest("GET", ts.URL, nil)
	vectors = append(vectors, vector{name: "unauthorized", req: req, want: 401})

	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.Header.Add("Authorization", "Bearer "+token)
	vectors = append(vectors, vector{name: "from head", req: req, want: 200})

	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	vectors = append(vectors, vector{name: "from cookie", req: req, want: 200})

	req, _ = http.NewRequest("GET", ts.URL+"/?"+ParamName+"="+token, nil)
	vectors = append(vectors, vector{name: "from cookie", req: req, want: 200})

	client := ts.Client()
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			res, err := client.Do(v.req)
			if err != nil {
				t.Fatalf("get fail %s", err)
			}
			if res.StatusCode != v.want {
				t.Fatalf("invalid status %d", res.StatusCode)
			}
			t.Logf("res status %d", res.StatusCode)
		})

	}

}

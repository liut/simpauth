# simpauth

For online user in http

## Usage

```go

import auth "github.com/liut/simpauth"

authoriz := auth.New(
		auth.WithCookie("myname", "/", "mydomain.net"), // custom cookie: name, path, domain
		auth.WithMaxAge(1800),                       // set maxage
		auth.WithRefresh(),                          // auto refresh cookie value
	)

func login(w http.ResponseWriter, r *http.Request) {
	// do login check
	var user = &User{
		UID:  "eagle",
		Name: "liut",
	}
	user.Refresh()
	authoriz.Signin(user, w)
}

func welcome(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		log.Print("userFromContext fail")
		w.WriteHeader(401)
		return
	}
	log.Printf("user %v", user.Name)
}

run() {
	mw := authoriz.Middleware()
	handler := mw(http.HandlerFunc(welcome)))

	// other routers
}

```

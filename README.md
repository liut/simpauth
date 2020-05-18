# simpauth

For online user in http

## Usage

```go

import auth "github.com/liut/simpauth"

func welcome(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		log.Print("userFromContext fail")
		w.WriteHeader(401)
		return
	}
	log.Printf("user %v", user.Name)
}

main() {
	mw := auth.Middleware(WithRefresh())
	handler := mw(http.HandlerFunc(welcome)))

	// other routers
}

```

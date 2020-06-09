package auth

import (
	"context"
)

type ctxKey int

// consts
const (
	UserKey ctxKey = iota
)

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

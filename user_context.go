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
func ContextWithUser(ctx context.Context, user IUser) context.Context {
	return context.WithValue(ctx, UserKey, user)
}

// UserFromContext ...
func UserFromContext(ctx context.Context) (IUser, bool) {
	if ctx == nil {
		return nil, false
	}
	if obj, ok := ctx.Value(UserKey).(IUser); ok {
		return obj, true
	}
	return nil, false
}

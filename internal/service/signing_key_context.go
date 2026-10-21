package service

import (
	"context"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type signingKeyContextKey struct{}

// WithSigningKey records the key verified by request signature middleware.
func WithSigningKey(ctx context.Context, key repository.UserPublicKey) context.Context {
	return context.WithValue(ctx, signingKeyContextKey{}, key)
}

// SigningKeyFromContext returns the identity key verified for this request.
func SigningKeyFromContext(ctx context.Context) (repository.UserPublicKey, bool) {
	key, ok := ctx.Value(signingKeyContextKey{}).(repository.UserPublicKey)
	return key, ok
}

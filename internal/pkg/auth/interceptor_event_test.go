package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type authTestServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s authTestServerStream) Context() context.Context { return s.ctx }

func TestEventSubscriptionRequiresSubscriberRole(t *testing.T) {
	assert.Equal(t, RoleSubscriber, methodRoles["/lippycat.events.v1.EventService/SubscribeEvents"])
	validator := NewValidator(Config{Enabled: true, APIKeys: []APIKey{
		{Key: "hunter-key", Role: RoleHunter},
		{Key: "subscriber-key", Role: RoleSubscriber},
	}})
	interceptor := StreamServerInterceptor(validator)
	info := &grpc.StreamServerInfo{FullMethod: "/lippycat.events.v1.EventService/SubscribeEvents", IsServerStream: true}
	handler := func(any, grpc.ServerStream) error { return nil }

	hunterContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(APIKeyMetadataKey, "hunter-key"))
	err := interceptor(nil, authTestServerStream{ctx: hunterContext}, info, handler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	subscriberContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(APIKeyMetadataKey, "subscriber-key"))
	require.NoError(t, interceptor(nil, authTestServerStream{ctx: subscriberContext}, info, handler))
}

func TestEventIngressRequiresHunterRole(t *testing.T) {
	assert.Equal(t, RoleHunter, methodRoles["/lippycat.events.v1.EventService/StreamEvents"])
	validator := NewValidator(Config{Enabled: true, APIKeys: []APIKey{
		{Key: "hunter-key", Role: RoleHunter},
		{Key: "subscriber-key", Role: RoleSubscriber},
	}})
	interceptor := StreamServerInterceptor(validator)
	info := &grpc.StreamServerInfo{FullMethod: "/lippycat.events.v1.EventService/StreamEvents", IsClientStream: true, IsServerStream: true}
	handler := func(any, grpc.ServerStream) error { return nil }

	subscriberContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(APIKeyMetadataKey, "subscriber-key"))
	err := interceptor(nil, authTestServerStream{ctx: subscriberContext}, info, handler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	hunterContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs(APIKeyMetadataKey, "hunter-key"))
	require.NoError(t, interceptor(nil, authTestServerStream{ctx: hunterContext}, info, handler))
}

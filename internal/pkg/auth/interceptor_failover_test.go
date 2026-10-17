package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestFailoverMethodsAuthorizeNodeAndPolicyAdministrationSeparately(t *testing.T) {
	validator := NewValidator(Config{Enabled: true, APIKeys: []APIKey{{Key: "node", Role: RoleHunter}, {Key: "admin", Role: RoleAdmin}}})
	for _, method := range []struct {
		name          string
		stream, admin bool
	}{
		{"/lippycat.data.RelayDataService/StreamRelayPackets", true, false},
		{"/lippycat.data.ReliablePacketService/StreamReliablePackets", true, false},
		{"/lippycat.management.FilterPolicyService/GetSnapshot", false, false},
		{"/lippycat.management.FilterPolicyService/SubscribeSnapshots", true, false},
		{"/lippycat.management.FilterPolicyService/ApplySnapshot", false, true},
		{"/lippycat.management.FilterPolicyService/PublishSnapshot", false, true},
	} {
		t.Run(method.name, func(t *testing.T) {
			for _, key := range []string{"node", "admin"} {
				ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(APIKeyMetadataKey, key))
				called := false
				var err error
				if method.stream {
					err = StreamServerInterceptor(validator)(nil, authTestServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: method.name}, func(any, grpc.ServerStream) error { called = true; return nil })
				} else {
					_, err = UnaryServerInterceptor(validator)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method.name}, func(context.Context, any) (any, error) { called = true; return nil, nil })
				}
				if method.admin && key == "node" {
					require.Equal(t, codes.Unauthenticated, status.Code(err))
					require.False(t, called)
				} else {
					require.NoError(t, err)
					require.True(t, called)
				}
			}
		})
	}
}

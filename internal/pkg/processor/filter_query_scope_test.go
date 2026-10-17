//go:build processor || tap || all

package processor

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestFilterQueriesKeepLocalSelectorsOffHunterRPC(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "query-scope", ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	for _, filter := range []*management.Filter{
		{Id: "distributed", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true},
		{Id: "central-only", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY},
	} {
		_, err = p.updateManagedFilter(filter)
		require.NoError(t, err)
	}
	validator := auth.NewValidator(auth.Config{Enabled: true, APIKeys: []auth.APIKey{
		{Key: "hunter-key", Role: auth.RoleHunter},
		{Key: "admin-key", Role: auth.RoleAdmin},
	}})
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(auth.UnaryServerInterceptor(validator)))
	management.RegisterManagementServiceServer(server, p)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
		require.NoError(t, listener.Close())
	})
	conn, err := grpc.NewClient("passthrough:///filter-query", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := management.NewManagementServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hunter := metadata.AppendToOutgoingContext(ctx, auth.APIKeyMetadataKey, "hunter-key")
	for _, id := range []string{"", "edge"} {
		response, err := client.GetFilters(hunter, &management.FilterRequest{HunterId: id})
		require.NoError(t, err)
		require.Len(t, response.Filters, 1, "local-only contents must not reach hunters, including empty legacy requests")
		require.Equal(t, "distributed", response.Filters[0].Id)
	}
	_, err = client.GetFiltersFromProcessor(hunter, &management.ProcessorFilterQuery{})
	require.Equal(t, codes.Unauthenticated, status.Code(err), "hunter role cannot use the administrative query")
	admin := metadata.AppendToOutgoingContext(ctx, auth.APIKeyMetadataKey, "admin-key")
	response, err := client.GetFiltersFromProcessor(admin, &management.ProcessorFilterQuery{})
	require.NoError(t, err)
	require.Len(t, response.Filters, 2, "authorized administration retains local-only visibility")
}

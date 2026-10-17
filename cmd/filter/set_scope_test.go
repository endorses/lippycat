//go:build cli || all

package filter

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	processorfiltering "github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestSetFilterSendsLocalOnlyScope(t *testing.T) {
	t.Setenv("LIPPYCAT_PRODUCTION", "false")
	SetFilterCmd.Flags().VisitAll(func(flag *pflag.Flag) {
		value, changed := flag.Value.String(), flag.Changed
		slice, isSlice := flag.Value.(pflag.SliceValue)
		var sliceValue []string
		if isSlice {
			sliceValue = append([]string(nil), slice.GetSlice()...)
		}
		t.Cleanup(func() {
			var err error
			if isSlice {
				err = slice.Replace(sliceValue)
			} else {
				err = flag.Value.Set(value)
			}
			if err != nil {
				t.Errorf("restore --%s: %v", flag.Name, err)
			}
			flag.Changed = changed
		})
	})
	manager := processorfiltering.NewManager("", nil, nil, nil, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	service := &radiusReplacementServer{manager: manager, results: make(chan radiusReplacementResult, 1)}
	management.RegisterManagementServiceServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Error("gRPC server did not stop")
		}
	})
	require.NoError(t, SetFilterCmd.ParseFlags([]string{
		"--processor", listener.Addr().String(), "--insecure",
		"--id", "private-selection", "--type", "sip_user", "--pattern", "alice",
		"--distribution-scope", "local_only",
	}))
	runSetFilter(SetFilterCmd, nil)
	select {
	case result := <-service.results:
		require.NoError(t, result.err)
		require.Equal(t, management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY, result.filter.DistributionScope)
	case <-time.After(time.Second):
		t.Fatal("CLI did not send local-only filter")
	}
	require.Len(t, manager.GetAll(), 1)
	require.Empty(t, manager.GetForHunter("edge"))
}

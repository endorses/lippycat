//go:build cli || all

package filter

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	processorfiltering "github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type radiusReplacementResult struct {
	filter *management.Filter
	err    error
}

type radiusReplacementServer struct {
	management.UnimplementedManagementServiceServer
	manager *processorfiltering.Manager
	results chan radiusReplacementResult
}

func (s *radiusReplacementServer) UpdateFilter(_ context.Context, f *management.Filter) (*management.FilterUpdateResult, error) {
	count, err := s.manager.Update(f)
	s.results <- radiusReplacementResult{filter: f, err: err}
	result := &management.FilterUpdateResult{Success: err == nil, HuntersUpdated: count}
	if err != nil {
		result.Error = err.Error()
	}
	return result, nil
}

func TestSetFilterPreservesRevisionWhenReplacingRADIUSWithBPF(t *testing.T) {
	t.Setenv("LIPPYCAT_PRODUCTION", "false")
	// The command uses package-level flag variables. Restore their values and
	// Changed bits so this invocation does not affect another command test.
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
	_, err := manager.Update(&management.Filter{Id: "shared", Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Revision: 1, Enabled: true})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	service := &radiusReplacementServer{manager: manager, results: make(chan radiusReplacementResult, 1)}
	management.RegisterManagementServiceServer(server, service)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-serveDone:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Error("gRPC server did not stop")
		}
	})

	require.NoError(t, SetFilterCmd.ParseFlags([]string{
		"--processor", listener.Addr().String(), "--insecure",
		"--id", "shared", "--type", "bpf", "--pattern", "udp", "--revision", "2",
	}))
	runSetFilter(SetFilterCmd, nil)
	select {
	case result := <-service.results:
		require.EqualValues(t, 2, result.filter.Revision, "explicit revision must survive conversion away from RADIUS")
		require.NoError(t, result.err)
	case <-time.After(time.Second):
		t.Fatal("CLI did not send filter replacement")
	}
	installed := manager.GetAll()
	require.Len(t, installed, 1)
	require.Equal(t, management.FilterType_FILTER_BPF, installed[0].Type)
	require.EqualValues(t, 2, installed[0].Revision)
}

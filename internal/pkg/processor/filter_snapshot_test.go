//go:build processor || tap || all

package processor

import (
	"context"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSubscribeFiltersNegotiatesAuthoritativeSnapshot(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "snapshot"}[modern], func(t *testing.T) {
			p, err := New(Config{ProcessorID: "snapshot-test", ListenAddr: "localhost:55555", MaxHunters: 10})
			require.NoError(t, err)
			defer p.Shutdown()
			_, err = p.filterManager.Update(&management.Filter{Id: "policy", Type: management.FilterType_FILTER_BPF, Pattern: "udp"})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &mockSubscribeFiltersServer{ctx: ctx}
			done := make(chan error, 1)
			go func() {
				done <- p.SubscribeFilters(&management.FilterRequest{HunterId: "hunter", SupportsSnapshot: modern}, stream)
			}()
			defer func() { cancel(); require.NoError(t, <-done) }()
			require.Eventually(t, func() bool { return len(stream.getUpdates()) == 1 }, time.Second, time.Millisecond)
			first := stream.getUpdates()[0]
			require.Equal(t, modern, first.Snapshot)
			if modern {
				require.Len(t, first.Filters, 1)
				require.Equal(t, "udp", first.Filters[0].Pattern)
				require.Nil(t, first.Filter)
			} else {
				require.Equal(t, management.FilterUpdateType_UPDATE_ADD, first.UpdateType)
				require.Equal(t, "udp", first.Filter.Pattern)
			}
			_, err = p.filterManager.Delete("policy")
			require.NoError(t, err)
			require.Eventually(t, func() bool { return len(stream.getUpdates()) == 2 }, time.Second, time.Millisecond)
			require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, stream.getUpdates()[1].UpdateType)
		})
	}
}

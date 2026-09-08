//go:build processor || tap || all

package processor

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type radiusFilterTestCapabilities struct{}

func (radiusFilterTestCapabilities) GetCapabilities(string) *management.HunterCapabilities {
	return &management.HunterCapabilities{FilterTypes: []string{"bpf", "radius_username"}, RadiusFilterVersion: 1}
}

func TestTapRADIUSFilterRPCRejectsBeforeMutation(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		name := "direct"
		if scoped {
			name = "processor-scoped"
		}
		for _, replace := range []bool{false, true} {
			operation := "create"
			if replace {
				operation = "replace"
			}
			t.Run(name+"/"+operation, func(t *testing.T) {
				path := t.TempDir() + "/filters.yaml"
				manager := filtering.NewManager(path, filtering.NewYAMLPersistence(), radiusFilterTestCapabilities{}, nil, nil)
				local := filtering.NewLocalTarget(filtering.LocalTargetConfig{})
				p := &Processor{filterManager: manager, filterTarget: local, proxyManager: proxy.NewManager(slog.Default(), "tap")}
				t.Cleanup(func() { p.proxyManager.Shutdown(time.Second) })
				if replace {
					original := &management.Filter{Id: "target", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true, Revision: 1}
					_, err := manager.Update(original)
					require.NoError(t, err)
					_, err = local.ApplyFilter(proto.Clone(original).(*management.Filter))
					require.NoError(t, err)
				} else {
					require.NoError(t, manager.Save())
				}
				before := manager.GetAll()
				localBefore := local.GetActiveFilters()
				diskBefore, err := os.ReadFile(path)
				require.NoError(t, err)
				updates := manager.AddChannel("capable-hunter")
				defer manager.RemoveChannel("capable-hunter", updates)
				filter := &management.Filter{Id: "target", Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Enabled: true, Revision: 2}
				var result *management.FilterUpdateResult
				if scoped {
					result, err = p.UpdateFilterOnProcessor(context.Background(), &management.ProcessorFilterRequest{ProcessorId: "tap", Filter: filter})
				} else {
					result, err = p.UpdateFilter(context.Background(), filter)
				}
				assert.Equal(t, codes.FailedPrecondition, status.Code(err))
				assert.Nil(t, result)
				assert.True(t, proto.Equal(&management.FilterResponse{Filters: before}, &management.FilterResponse{Filters: manager.GetAll()}), "rejection must not commit the filter")
				assert.True(t, proto.Equal(&management.FilterResponse{Filters: localBefore}, &management.FilterResponse{Filters: local.GetActiveFilters()}), "local capture policy must stay intact")
				diskAfter, readErr := os.ReadFile(path)
				require.NoError(t, readErr)
				assert.Equal(t, diskBefore, diskAfter, "rejection must not persist the filter")
				select {
				case <-updates:
					t.Error("rejection distributed a filter update")
				default:
				}
				// A rejected revision must remain available to a supported target.
				// Change the pattern so an incorrectly committed revision cannot be
				// mistaken for an idempotent retry by the manager.
				filter.Pattern = "bob"
				_, err = manager.Update(filter)
				require.NoError(t, err, "rejection must not consume the revision")
			})
		}
	}
}

func TestProcessorRADIUSFilterRPCRemainsSupported(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		name := "direct"
		if scoped {
			name = "processor-scoped"
		}
		t.Run(name, func(t *testing.T) {
			manager := filtering.NewManager("", nil, radiusFilterTestCapabilities{}, nil, nil)
			p := &Processor{filterManager: manager, filterTarget: filtering.NewHunterTarget(manager), proxyManager: proxy.NewManager(slog.Default(), "central")}
			t.Cleanup(func() { p.proxyManager.Shutdown(time.Second) })
			updates := manager.AddChannel("capable-hunter")
			defer manager.RemoveChannel("capable-hunter", updates)
			filter := &management.Filter{Id: "target", Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Enabled: true, Revision: 1}
			var result *management.FilterUpdateResult
			var err error
			if scoped {
				result, err = p.UpdateFilterOnProcessor(context.Background(), &management.ProcessorFilterRequest{ProcessorId: "central", Filter: filter})
			} else {
				result, err = p.UpdateFilter(context.Background(), filter)
			}
			require.NoError(t, err)
			require.True(t, result.Success)
			require.EqualValues(t, 1, result.HuntersUpdated)
			stored := manager.GetAll()
			require.Len(t, stored, 1)
			require.True(t, proto.Equal(filter, stored[0]))
			select {
			case update := <-updates:
				require.True(t, proto.Equal(filter, update.Filter))
			default:
				t.Fatal("supported filter was not distributed")
			}
		})
	}
}

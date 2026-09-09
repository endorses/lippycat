//go:build (processor || tap || all) && li

package processor

import (
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/stretchr/testify/require"
)

type liFilterBPFRecorder struct{ expressions []string }

func (r *liFilterBPFRecorder) SetBPFFilter(expression string) error {
	r.expressions = append(r.expressions, expression)
	return nil
}

func TestLIFilterPusherDistributedAndLocalTargets(t *testing.T) {
	for _, local := range []bool{false, true} {
		name := "distributed"
		if local {
			name = "local"
		}
		t.Run(name, func(t *testing.T) {
			manager := filtering.NewManager(filepath.Join(t.TempDir(), "filters.yaml"), filtering.NewYAMLPersistence(), radiusFilterTestCapabilities{}, nil, nil)
			p := &Processor{filterManager: manager, filterTarget: filtering.NewHunterTarget(manager)}
			bpf := &liFilterBPFRecorder{}
			if local {
				target := filtering.NewLocalTarget(filtering.LocalTargetConfig{})
				target.SetBPFUpdater(bpf)
				p.SetFilterTarget(target)
			}
			updates := manager.AddChannel("hunter")
			defer manager.RemoveChannel("hunter", updates)
			assertUpdate := func(want management.FilterUpdateType) {
				t.Helper()
				select {
				case update := <-updates:
					require.Equal(t, want, update.UpdateType)
					require.Equal(t, "li-filter", update.Filter.Id)
				default:
					t.Fatal("LI filter change was not distributed")
				}
				select {
				case duplicate := <-updates:
					t.Fatalf("LI filter change distributed twice: %v", duplicate)
				default:
				}
			}
			pusher := &processorFilterPusher{p: p}
			require.NoError(t, pusher.UpdateFilter(&management.Filter{Id: "li-filter", Type: management.FilterType_FILTER_BPF, Pattern: "udp port 1812", Enabled: true}))
			require.Len(t, manager.GetAll(), 1)
			require.Equal(t, 1, p.filterTarget.FilterCount())
			assertUpdate(management.FilterUpdateType_UPDATE_ADD)
			if local {
				require.Len(t, bpf.expressions, 1)
				require.Contains(t, bpf.expressions[0], "udp port 1812")
			}
			require.NoError(t, pusher.DeleteFilter("li-filter"))
			require.Empty(t, manager.GetAll())
			require.Zero(t, p.filterTarget.FilterCount())
			assertUpdate(management.FilterUpdateType_UPDATE_DELETE)
			if local {
				require.Len(t, bpf.expressions, 2)
				require.Empty(t, bpf.expressions[1], "local capture filter must be cleared")
			}
		})
	}
}

//go:build (processor || tap || all) && li

package processor

import (
	"errors"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestManagedMutationLIPusherParity(t *testing.T) {
	p, store, target := mutationProcessor(t)
	pusher := &processorFilterPusher{p: p}
	f := &management.Filter{Id: "li-sensitive-id", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}
	store.fail = errors.New("save failed")
	require.Error(t, pusher.UpdateFilter(f))
	require.Zero(t, target.updates)
	store.fail = nil
	require.NoError(t, pusher.UpdateFilter(f))
	require.Equal(t, 1, target.updates)
	store.fail = errors.New("save failed")
	require.Error(t, pusher.DeleteFilter(f.Id))
	require.Zero(t, target.deletes)
	store.fail = nil
	require.NoError(t, pusher.DeleteFilter(f.Id))
	require.Equal(t, 1, target.deletes)
	require.NoError(t, pusher.DeleteFilter(f.Id))
	require.Equal(t, 1, target.deletes, "recovered cleanup of an absent filter is idempotent")
}

package filtering

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestSubscribeSnapshotOrdersPolicyAndLiveUpdates(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	filter := func(pattern string) *management.Filter {
		return &management.Filter{Id: "policy", Type: management.FilterType_FILTER_BPF, Pattern: pattern}
	}
	_, err := m.Update(filter("udp"))
	require.NoError(t, err)
	_, err = m.Update(filter("tcp"))
	require.NoError(t, err)
	ch, snapshot := m.SubscribeSnapshot("hunter")
	require.Len(t, snapshot, 1)
	require.True(t, proto.Equal(filter("tcp"), snapshot[0]))
	select {
	case update := <-ch:
		t.Fatalf("pre-snapshot update queued: %v", update)
	default:
	}
	_, err = m.Update(filter("icmp"))
	require.NoError(t, err)
	require.Equal(t, "icmp", (<-ch).Filter.Pattern)
	_, err = m.Delete("policy")
	require.NoError(t, err)
	require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, (<-ch).UpdateType)
	reconnect, empty := m.SubscribeSnapshot("hunter")
	require.Empty(t, empty)
	_, open := <-ch
	require.False(t, open)
	m.RemoveChannel("hunter", ch) // Old stream cleanup must not remove reconnect.
	_, err = m.Update(filter("udp"))
	require.NoError(t, err)
	require.Equal(t, "udp", (<-reconnect).Filter.Pattern)
	m.RemoveChannel("hunter", reconnect)
}

func TestSubscribeSnapshotSerializesConcurrentMutation(t *testing.T) {
	caps := &radiusBlockingCapabilities{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewManager("", nil, caps, nil, nil)
	filter := func(revision uint64) *management.Filter {
		return &management.Filter{Id: "policy", Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Revision: revision, Enabled: true}
	}
	_, err := m.Update(filter(1))
	require.NoError(t, err)
	caps.armed.Store(true)
	type subscription struct {
		ch      chan *management.FilterUpdate
		filters []*management.Filter
	}
	ready := make(chan subscription, 1)
	go func() { ch, filters := m.SubscribeSnapshot("hunter"); ready <- subscription{ch, filters} }()
	<-caps.entered
	changed := make(chan error, 1)
	go func() { _, err := m.Update(filter(2)); changed <- err }()
	close(caps.release)
	sub := <-ready
	require.NoError(t, <-changed)
	require.Equal(t, uint64(1), sub.filters[0].Revision)
	require.Equal(t, uint64(2), (<-sub.ch).Filter.Revision)
	m.RemoveChannel("hunter", sub.ch)
}

func TestScopeRemovalTimeoutForcesAuthoritativeReconnect(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	ch := make(chan *management.FilterUpdate, 1)
	m.channels["old-hunter"] = ch
	_, err := m.Update(&management.Filter{Id: "policy", Type: management.FilterType_FILTER_BPF, Pattern: "udp", TargetHunters: []string{"old-hunter"}})
	require.NoError(t, err)
	// The queued ADD fills the channel. Losing the scope-removal DELETE must
	// close this stream rather than leave its recipient authorized indefinitely.
	_, err = m.Update(&management.Filter{Id: "policy", Type: management.FilterType_FILTER_BPF, Pattern: "udp", TargetHunters: []string{"new-hunter"}})
	require.NoError(t, err)
	<-ch
	_, open := <-ch
	require.False(t, open)
	reconnect, snapshot := m.SubscribeSnapshot("old-hunter")
	require.Empty(t, snapshot)
	m.RemoveChannel("old-hunter", reconnect)
}

package dhcp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func message(t *testing.T, kind byte) *Message {
	t.Helper()
	m, err := Decode(packet(kind, 255))
	require.NoError(t, err)
	return m
}
func tracker(t *testing.T, c Config) *Tracker {
	t.Helper()
	tr, err := NewTracker(c)
	require.NoError(t, err)
	return tr
}

func TestAssociationExchangeRetransmitsServersAddressChanges(t *testing.T) {
	tr := tracker(t, DefaultConfig())
	at := time.Unix(1000, 0)
	request := message(t, 1)
	first := tr.Observe("sensor/epoch/input", at, request)
	require.Equal(t, AssociationRequest, first.Status)
	require.Equal(t, first.ID, tr.Observe("sensor/epoch/input", at.Add(time.Second), request).ID)
	reply := message(t, 2)
	reply.ServerIdentifier = netip.MustParseAddr("192.0.2.1")
	reply.OfferedAddress = netip.MustParseAddr("192.0.2.50")
	offer := tr.Observe("sensor/epoch/input", at.Add(2*time.Second), reply)
	require.Equal(t, AssociationUnique, offer.Status)
	require.Equal(t, first.ID, offer.ID)
	reply.ServerIdentifier = netip.MustParseAddr("192.0.2.2")
	offer2 := tr.Observe("sensor/epoch/input", at.Add(3*time.Second), reply)
	require.Equal(t, first.ID, offer2.ID)
	require.NotEqual(t, offer.ServerID, offer2.ServerID)
	request.MessageType = 3
	request.ServerIdentifier = netip.MustParseAddr("192.0.2.1")
	request.ClientAddress = reply.OfferedAddress
	selected := tr.Observe("sensor/epoch/input", at.Add(4*time.Second), request)
	require.Equal(t, first.ID, selected.ID)
	require.Equal(t, offer.ServerID, selected.ServerID)
	reply.MessageType = 5
	require.Equal(t, AssociationMissing, tr.Observe("sensor/epoch/input", at.Add(5*time.Second), reply).Status)
	reply.ServerIdentifier = request.ServerIdentifier
	ack := tr.Observe("sensor/epoch/input", at.Add(6*time.Second), reply)
	require.Equal(t, AssociationUnique, ack.Status)
	require.Equal(t, first.ID, ack.ID)
}

func TestAssociationScopeIdentityRelayAndAmbiguity(t *testing.T) {
	tr := tracker(t, DefaultConfig())
	at := time.Unix(1000, 0)
	request := message(t, 1)
	request.ClientIdentifier = []byte{0, 1}
	a := tr.Observe("sensor-a", at, request)
	b := tr.Observe("sensor-b", at, request)
	require.NotEqual(t, a.ID, b.ID)
	reply := message(t, 2)
	require.Equal(t, AssociationUnique, tr.Observe("sensor-a", at, reply).Status)
	require.Equal(t, AssociationMissing, tr.Observe("sensor-c", at, reply).Status)
	reply.HardwareAddress[0] = 99
	require.Equal(t, AssociationMissing, tr.Observe("sensor-a", at, reply).Status)
	reply.HardwareAddress[0] = 1
	request.ClientIdentifier = []byte{0, 2}
	tr.Observe("sensor-a", at, request)
	require.Equal(t, AssociationAmbiguous, tr.Observe("sensor-a", at, reply).Status)
	reply.ClientIdentifier = []byte{0, 1}
	require.Equal(t, a.ID, tr.Observe("sensor-a", at, reply).ID)
	reply.RelayAddress = netip.MustParseAddr("192.0.2.254")
	require.Equal(t, AssociationMissing, tr.Observe("sensor-a", at, reply).Status)
	request.RelayAddress = reply.RelayAddress
	request.ClientIdentifier = reply.ClientIdentifier
	relayed := tr.Observe("sensor-a", at, request)
	require.NotEqual(t, a.ID, relayed.ID)
	require.Equal(t, relayed.ID, tr.Observe("sensor-a", at, reply).ID)
}

func TestAssociationExpiryEvictionResetAndLateCapture(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEntries = 1
	cfg.MaxBytes = EntryBytes
	cfg.Timeout = time.Minute
	tr := tracker(t, cfg)
	at := time.Unix(1000, 0)
	request := message(t, 1)
	first := tr.Observe("scope", at, request)
	second := *request
	second.TransactionID++
	tr.Observe("scope", at, &second)
	require.Equal(t, uint64(1), tr.Stats().Evicted)
	require.Equal(t, EntryBytes, tr.Stats().Bytes)
	require.Equal(t, AssociationMissing, tr.Observe("scope", at, message(t, 2)).Status)
	tr.Advance(at.Add(time.Minute))
	require.Zero(t, tr.Stats().Entries)
	// Even a late request within the current time window must not resurrect
	// an exchange which has already been expired at the watermark.
	require.Equal(t, AssociationExpired, tr.Observe("scope", at.Add(30*time.Second), request).Status)
	require.Zero(t, tr.Stats().Entries)
	require.Equal(t, uint64(1), tr.Stats().Expired)
	require.Equal(t, AssociationExpired, tr.Observe("scope", at, request).Status)
	require.Zero(t, tr.Stats().Entries)
	next := tr.Observe("scope", at.Add(2*time.Minute), request)
	require.NotEqual(t, first.ID, next.ID)
	tr.Reset()
	require.Zero(t, tr.Stats().Entries)
	require.Zero(t, tr.Stats().Bytes)
	require.Equal(t, AssociationMissing, tr.Observe("scope", at, message(t, 2)).Status)
	cfg.MaxBytes = EntryBytes - 1
	tr = tracker(t, cfg)
	require.Equal(t, AssociationCapacitySuppressed, tr.Observe("scope", at, request).Status)
	require.Zero(t, tr.Stats().Entries)
}

func TestAssociationRolesAndMalformed(t *testing.T) {
	tr := tracker(t, DefaultConfig())
	at := time.Unix(1000, 0)
	for _, kind := range []byte{4, 7} {
		require.Equal(t, AssociationNotApplicable, tr.Observe("s", at, message(t, kind)).Status)
	}
	m := message(t, 1)
	m.Partial = true
	require.Equal(t, AssociationNotApplicable, tr.Observe("s", at, m).Status)
	require.Equal(t, AssociationMissing, tr.Observe("s", at, message(t, 5)).Status)
	tr.Observe("s", at, message(t, 8))
	require.Equal(t, AssociationUnique, tr.Observe("s", at, message(t, 5)).Status)
	require.Equal(t, AssociationMissing, tr.Observe("s", at, message(t, 2)).Status)
	// Positive values are required even when a caller intends no associations.
	for _, c := range []Config{{}, {MaxEntries: 1, MaxBytes: 1}, {MaxEntries: -1, MaxBytes: 1, Timeout: 1}} {
		_, err := NewTracker(c)
		require.Error(t, err)
	}
}

func TestAssociationConcurrent(t *testing.T) {
	tr := tracker(t, DefaultConfig())
	m := message(t, 1)
	at := time.Unix(1000, 0)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tr.Observe("s", at, m)
				tr.Stats()
				tr.Advance(at)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, tr.Stats().Entries)
}

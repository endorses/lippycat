//go:build li

package delivery

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCorrelationPublicationPartialFanout(t *testing.T) {
	m, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer m.Stop()
	c := NewClient(m, DefaultClientConfig())
	defer c.Stop()
	xid, good, missing, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, m.AddDestination(&li.Destination{DID: good, Address: "127.0.0.1", Port: 1, ProtocolType: "X2"}))
	require.NoError(t, m.AddDestination(&li.Destination{DID: other, Address: "127.0.0.1", Port: 1, ProtocolType: "X3"}))
	publications := 0
	callback := func() {
		require.True(t, c.admissionMu.TryLock(), "publication callback must run outside admission lock")
		c.admissionMu.Unlock()
		publications++
	}
	// Later rejection must not hide an earlier accepted destination.
	err = c.SendX2WithMetadataAndPublication(xid, []uuid.UUID{good, missing}, []byte("synthetic-pdu"), DeliveryMetadata{}, callback)
	require.Error(t, err)
	require.Equal(t, 1, publications)
	require.EqualValues(t, 1, c.Stats().QueueDepth)
	// Earlier rejection likewise must not hide a later acceptance.
	err = c.SendX2WithMetadataAndPublication(xid, []uuid.UUID{missing, good}, []byte("synthetic-pdu"), DeliveryMetadata{}, callback)
	require.Error(t, err)
	require.Equal(t, 2, publications)
	require.NoError(t, c.SendX2WithMetadataAndPublication(xid, []uuid.UUID{other}, []byte("synthetic-pdu"), DeliveryMetadata{}, callback))
	require.Equal(t, 2, publications, "protocol gating is not publication")
	require.ErrorIs(t, c.SendX2WithMetadataAndPublication(xid, nil, []byte("synthetic-pdu"), DeliveryMetadata{}, callback), ErrNoDestinations)
	require.Equal(t, 2, publications)
}

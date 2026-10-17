package packetreceipt

import (
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func custodyTestConfig(t *testing.T) StoreConfig {
	t.Helper()
	return StoreConfig{Directory: filepath.Join(t.TempDir(), "custody"), DestinationID: "central", Protection: "private", MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxSessions: 4, MaxRecords: 8, MaxLossRanges: 4}
}
func custodyTestMessage(sequence uint64) *data.ReliablePacketMessage {
	id := &data.RawPacketIdentity{SourceId: "edge", ProducerSessionId: "capture-session", CaptureEpoch: "epoch", DestinationId: "central", AckScope: "central"}
	return &data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: &data.PacketBatch{HunterId: id.SourceId, ProducerSessionId: id.ProducerSessionId, CaptureEpoch: id.CaptureEpoch, Sequence: sequence, Packets: []*data.CapturedPacket{{Data: []byte("raw packet bytes"), TimestampNs: 1234, InterfaceName: "eth0"}}}}
}

func TestCustodyReplayRotatesBetweenBusyOrigins(t *testing.T) {
	config := custodyTestConfig(t)
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	for _, origin := range []string{"origin-a", "origin-b"} {
		for seq := uint64(1); seq <= 2; seq++ {
			message := custodyTestMessage(seq)
			message.Identity.SourceId = origin
			message.Batch.HunterId = origin
			_, _, err := store.Accept(message)
			require.NoError(t, err)
		}
	}
	first, err := store.Pending(1)
	require.NoError(t, err)
	require.Len(t, first, 1)
	second, err := store.Pending(1)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.NotEqual(t, first[0].Identity.SourceId, second[0].Identity.SourceId, "an origin with continuous backlog must not starve another origin")
	require.Equal(t, uint64(1), second[0].Batch.Sequence)
}

func TestCustodyRecoveryBeforeAndAfterProcessingCheckpoint(t *testing.T) {
	config := custodyTestConfig(t)
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	message := custodyTestMessage(1)
	receipt, duplicate, err := store.Accept(message)
	require.NoError(t, err)
	require.False(t, duplicate)
	require.Equal(t, uint64(1), receipt.Sequence)
	require.NoError(t, store.Close()) // receiver commit, response lost, process crashed
	store, err = Open(config)
	require.NoError(t, err)
	pending, err := store.Pending(1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(message.Batch, pending[0].Batch))
	_, duplicate, err = store.Accept(message)
	require.NoError(t, err)
	require.True(t, duplicate)
	require.NoError(t, store.Processed(message.Identity, 1, receipt.ContentSha256))
	require.NoError(t, store.Close())
	store, err = Open(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	pending, err = store.Pending(4)
	require.NoError(t, err)
	require.Empty(t, pending)
	_, duplicate, err = store.Accept(message)
	require.NoError(t, err)
	require.True(t, duplicate)
	conflict := proto.Clone(message).(*data.ReliablePacketMessage)
	conflict.Batch.Packets[0].Data = []byte("different data")
	_, _, err = store.Accept(conflict)
	require.ErrorContains(t, err, "conflicting")
}

func TestCustodyNeverAcknowledgesHolesAndRetainsBoundedDuplicateHistory(t *testing.T) {
	config := custodyTestConfig(t)
	config.MaxRecords = 2
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	for _, sequence := range []uint64{1, 3} {
		message := custodyTestMessage(sequence)
		receipt, _, err := store.Accept(message)
		require.NoError(t, err)
		require.Equal(t, sequence, receipt.Sequence)
		require.NoError(t, store.Processed(message.Identity, sequence, receipt.ContentSha256))
	}
	_, _, err = store.Accept(custodyTestMessage(4))
	require.ErrorContains(t, err, "history limit")
	// Selective ACK 3 makes no assertion that missing sequence 2 arrived.
	_, duplicate, err := store.Accept(custodyTestMessage(3))
	require.NoError(t, err)
	require.True(t, duplicate)
	retire := custodyTestMessage(1)
	retire.Batch = nil
	retire.RetireSession = true
	_, _, err = store.Accept(retire)
	require.NoError(t, err)
	_, _, err = store.Accept(custodyTestMessage(1))
	require.ErrorContains(t, err, "retired")
}

func TestCustodyRejectsMissingRecoveryStateAndChangedDestination(t *testing.T) {
	config := custodyTestConfig(t)
	_, err := Open(config)
	require.Error(t, err)
	require.NoError(t, Initialize(config))
	changed := config
	changed.DestinationID = "different"
	_, err = Open(changed)
	require.ErrorContains(t, err, "identity")
}

func TestCustodyLossOnlyProgressAndPendingPayloadSurviveLossCoverage(t *testing.T) {
	config := custodyTestConfig(t)
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	message := custodyTestMessage(2)
	_, _, err = store.Accept(message)
	require.NoError(t, err)
	message.Batch = nil
	message.LossGeneration = 1
	message.Losses = []*data.RawPacketLossRange{{First: 1, Last: 2}}
	receipt, _, err := store.Accept(message)
	require.NoError(t, err)
	require.Equal(t, uint64(1), receipt.LossGeneration)
	require.NoError(t, store.Close())
	store, err = Open(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	pending, err := store.Pending(2)
	require.NoError(t, err)
	require.Len(t, pending, 1) // accepted custody cannot be removed by source retention loss
	_, _, err = store.Accept(custodyTestMessage(1))
	require.ErrorContains(t, err, "accounted loss")
}

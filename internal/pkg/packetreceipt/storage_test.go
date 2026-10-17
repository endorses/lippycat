package packetreceipt

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func encryptedCustodyConfig(t *testing.T) StoreConfig {
	t.Helper()
	config := custodyTestConfig(t)
	key := filepath.Join(t.TempDir(), "custody.key")
	require.NoError(t, os.WriteFile(key, bytes.Repeat([]byte{43}, securestore.KeyBytes), 0600))
	config.Protection = "encrypted"
	config.Keys = securestore.KeyConfig{Active: securestore.KeyRef{ID: "custody-key", File: key}}
	return config
}
func TestEncryptedCustodyRecoveryAndIdentityBinding(t *testing.T) {
	config := encryptedCustodyConfig(t)
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	message := custodyTestMessage(1)
	receipt, duplicate, err := store.Accept(message)
	require.NoError(t, err)
	require.False(t, duplicate)
	require.NoError(t, store.Close())
	for _, name := range []string{custodyName, identityName} {
		encoded, err := os.ReadFile(filepath.Join(config.Directory, name))
		require.NoError(t, err)
		require.Equal(t, "LCS1", string(encoded[:4]))
		require.Equal(t, uint16(securestore.PacketCustodyState), binary.BigEndian.Uint16(encoded[6:8]))
		require.NotContains(t, string(encoded), "raw packet bytes")
		require.NotContains(t, string(encoded), "edge")
	}
	store, err = Open(config)
	require.NoError(t, err)
	pending, err := store.Pending(2)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(message.Batch, pending[0].Batch))
	_, duplicate, err = store.Accept(message)
	require.NoError(t, err)
	require.True(t, duplicate)
	require.NoError(t, store.Processed(message.Identity, 1, receipt.ContentSha256))
	require.NoError(t, store.Processed(message.Identity, 1, receipt.ContentSha256))
	require.NoError(t, store.Close())
	changed := config
	changed.DestinationID = "wrong-destination"
	_, err = Open(changed)
	require.ErrorContains(t, err, "identity")
}
func TestEncryptedCustodyNeverRecreatesMissingCheckpointOrLedger(t *testing.T) {
	for _, missing := range []string{identityName, custodyName, "ledger"} {
		t.Run(missing, func(t *testing.T) {
			config := encryptedCustodyConfig(t)
			require.NoError(t, Initialize(config))
			name := missing
			if name == "ledger" {
				keys, err := securestore.LoadKeyring(config.Keys)
				require.NoError(t, err)
				name = keys.UsageFileName()
			}
			require.NoError(t, os.Remove(filepath.Join(config.Directory, name)))
			_, err := Open(config)
			require.Error(t, err)
			require.Error(t, Initialize(config), "partial stores must not be reinitialized")
			_, err = os.Stat(filepath.Join(config.Directory, name))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}
func TestEncryptedCustodyRejectsWrongKeyAndTamperedSnapshot(t *testing.T) {
	config := encryptedCustodyConfig(t)
	require.NoError(t, Initialize(config))
	original, err := os.ReadFile(filepath.Join(config.Directory, custodyName))
	require.NoError(t, err)
	original[len(original)-1] ^= 1
	require.NoError(t, os.WriteFile(filepath.Join(config.Directory, custodyName), original, 0600))
	_, err = Open(config)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(config.Keys.Active.File, bytes.Repeat([]byte{44}, securestore.KeyBytes), 0600))
	_, err = Open(config)
	require.Error(t, err)
}
func TestCustodyPublicationFailuresDoNotIssueReceipts(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-publication", true: "uncertain-publication"}[uncertain], func(t *testing.T) {
			config := custodyTestConfig(t)
			require.NoError(t, Initialize(config))
			store, err := Open(config)
			require.NoError(t, err)
			realReplace := store.fs.replace
			injected := errors.New("injected storage fault")
			store.fs.replace = func(name string, payload []byte) (securestore.Outcome, error) {
				if uncertain {
					out, err := realReplace(name, payload)
					if err != nil {
						return out, err
					}
					return securestore.Uncertain, injected
				}
				return securestore.NotCommitted, injected
			}
			receipt, duplicate, err := store.Accept(custodyTestMessage(1))
			require.ErrorIs(t, err, injected)
			require.Nil(t, receipt)
			require.False(t, duplicate)
			if uncertain {
				_, err := store.Pending(1)
				require.ErrorContains(t, err, "uncertain")
			} else {
				pending, err := store.Pending(1)
				require.NoError(t, err)
				require.Empty(t, pending)
			}
			require.NoError(t, store.Close())
			store, err = Open(config)
			require.NoError(t, err)
			defer func() { require.NoError(t, store.Close()) }()
			pending, err := store.Pending(1)
			require.NoError(t, err)
			if uncertain {
				require.Len(t, pending, 1)
			} else {
				require.Empty(t, pending)
			}
			_, duplicate, err = store.Accept(custodyTestMessage(1))
			require.NoError(t, err)
			require.Equal(t, uncertain, duplicate)
		})
	}
}
func TestCustodyRetirementRetryAndSessionHistoryArePermanent(t *testing.T) {
	config := custodyTestConfig(t)
	config.MaxSessions = 1
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	message := custodyTestMessage(1)
	receipt, _, err := store.Accept(message)
	require.NoError(t, err)
	require.NoError(t, store.Processed(message.Identity, 1, receipt.ContentSha256))
	message.Batch = nil
	message.RetireSession = true
	retired, duplicate, err := store.Accept(message)
	require.NoError(t, err)
	require.True(t, retired.Retired)
	require.False(t, duplicate)
	require.NoError(t, store.Close())
	store, err = Open(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	retried, duplicate, err := store.Accept(message)
	require.NoError(t, err)
	require.True(t, duplicate)
	require.True(t, proto.Equal(retired, retried))
	_, _, err = store.Accept(custodyTestMessage(1))
	require.ErrorContains(t, err, "retired")
	fresh := custodyTestMessage(1)
	fresh.Identity.ProducerSessionId = "new-session"
	fresh.Batch.ProducerSessionId = "new-session"
	_, _, err = store.Accept(fresh)
	require.ErrorContains(t, err, "session history limit")
}
func TestCustodyCheckpointRejectsNestedAllocationsBeforeDecode(t *testing.T) {
	config := custodyTestConfig(t)
	config.MaxSessions = 1
	config.MaxRecords = 1
	config.MaxLossRanges = 1
	tests := []string{
		`{"sessions":{"one":{},"two":{}}}`,
		`{"sessions":{"one":{"records":[{},{}]}}}`,
		`{"sessions":{"one":{"losses":[{},{}]}}}`,
		`{"sessions":{},"sessions":{}}`,
		`{"payload":"` + strings.Repeat("A", 6000) + `"}`,
		`{"unknown":` + strings.Repeat(`{"unknown":`, 13) + `0` + strings.Repeat(`}`, 13) + `}`,
	}
	for _, encoded := range tests {
		require.Error(t, validateJSONBounds([]byte(encoded), config))
	}
	require.NoError(t, validateJSONBounds([]byte(`{"sessions":{"one":{"records":[{"payload":"YWJj"}]}}}`), config))
}
func TestCustodyRejectsSnapshotPayloadCorruption(t *testing.T) {
	config := custodyTestConfig(t)
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	_, _, err = store.Accept(custodyTestMessage(1))
	require.NoError(t, err)
	changed := store.clone()
	for _, session := range changed.Sessions {
		session.Records[0].Payload = []byte("invalid protobuf")
	}
	// Bypass commit validation to emulate an externally corrupted private snapshot.
	encoded, err := json.Marshal(changed)
	require.NoError(t, err)
	framed, err := store.protect(custodyName, encoded)
	require.NoError(t, err)
	_, err = store.dir.Replace(custodyName, framed)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	_, err = Open(config)
	require.Error(t, err)
}
func TestCustodyProtobufDecodeBudget(t *testing.T) {
	batch := &data.PacketBatch{Packets: make([]*data.CapturedPacket, 65537)}
	for i := range batch.Packets {
		batch.Packets[i] = &data.CapturedPacket{}
	}
	encoded, err := proto.Marshal(batch)
	require.NoError(t, err)
	require.ErrorContains(t, validateBatchWire(encoded, len(encoded)), "decoded message limit")
	require.ErrorContains(t, validateBatchWire([]byte{0x23, 0x24}, 4096), "groups")
}

func TestCustodyDuplicateControlsAvoidNewPublications(t *testing.T) {
	config := custodyTestConfig(t)
	require.NoError(t, Initialize(config))
	store, err := Open(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	losses := custodyTestMessage(1)
	losses.Batch = nil
	losses.LossGeneration = 1
	losses.Losses = []*data.RawPacketLossRange{{First: 1, Last: 2}}
	first, duplicate, err := store.Accept(losses)
	require.NoError(t, err)
	require.False(t, duplicate)
	var writes int
	realReplace := store.fs.replace
	store.fs.replace = func(name string, payload []byte) (securestore.Outcome, error) {
		writes++
		return realReplace(name, payload)
	}
	retry, duplicate, err := store.Accept(losses)
	require.NoError(t, err)
	require.True(t, duplicate)
	require.True(t, proto.Equal(first, retry))
	require.Zero(t, writes)
	conflict := proto.Clone(losses).(*data.ReliablePacketMessage)
	conflict.Losses[0].Last++
	_, _, err = store.Accept(conflict)
	require.ErrorContains(t, err, "conflicting raw loss generation")
	losses.Batch = nil
	losses.Losses = nil
	losses.LossGeneration = 0
	losses.RetireSession = true
	_, _, err = store.Accept(losses)
	require.NoError(t, err)
	writes = 0
	_, duplicate, err = store.Accept(losses)
	require.NoError(t, err)
	require.True(t, duplicate)
	require.Zero(t, writes)
}

func TestCustodyProtectionMustBeExplicitAndKeysMatchProfile(t *testing.T) {
	config := custodyTestConfig(t)
	config.Protection = ""
	require.Error(t, config.Validate())
	config.Protection = "encrypted"
	require.Error(t, config.Validate())
	config = encryptedCustodyConfig(t)
	config.Protection = "private"
	require.Error(t, config.Validate())
}

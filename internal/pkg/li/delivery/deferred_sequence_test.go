//go:build li && linux

package delivery

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDeferredX3PermitCompletesOnlySequenceAndPersistsFinalCheckpoint(t *testing.T) {
	config, manager, did, xid, metadata, template := x3ClientFixture(t)
	client := NewClient(manager, config)
	require.NoError(t, client.Err())
	defer client.Stop()
	checkpoint, err := x2x3.ProductSequenceCheckpoint(template)
	require.NoError(t, err)
	permit, err := client.PrepareDeferredX3(xid, did, template, metadata, checkpoint.Context)
	require.NoError(t, err)
	require.Error(t, client.SendAcceptedX3(permit), "ordinary emission cannot leak the unsequenced template")
	require.Zero(t, client.X3JournalStats().Persisted)
	require.NoError(t, client.SendAcceptedX3WithSequence(permit, 17))
	require.Error(t, client.SendAcceptedX3WithSequence(permit, 18), "a permit remains one-use")
	require.NoError(t, client.FlushPersistence(context.Background()))
	client.Stop()
	client = NewClient(manager, config)
	require.NoError(t, client.Err())
	defer client.Stop()
	var final []byte
	require.NoError(t, client.x3Journal.VisitHeld(func(record JournalRecord) error { final = append([]byte(nil), record.Data...); return nil }))
	require.NotEmpty(t, final)
	finalCheckpoint, err := x2x3.ProductSequenceCheckpoint(final)
	require.NoError(t, err)
	require.Equal(t, uint32(18), finalCheckpoint.Next)
	before, after := x2x3.PDU{}, x2x3.PDU{}
	require.NoError(t, before.UnmarshalBinary(template))
	require.NoError(t, after.UnmarshalBinary(final))
	require.Equal(t, before.Header, after.Header)
	require.Equal(t, before.Payload, after.Payload)
	for index, attribute := range before.Attributes {
		if attribute.Type != x2x3.AttrSequenceNumber {
			require.Equal(t, attribute, after.Attributes[index])
		}
	}
}

func TestOrdinaryDeferredDeliveryDoesNotAccumulatePersistentCallGates(t *testing.T) {
	config, manager, did, xid, metadata, template := x3ClientFixture(t)
	config.X3SpoolDir, config.X3SpoolKeyFile, config.X3SpoolKeyID = "", "", ""
	config.X3SpoolMaxBytes = 0
	metadata.CallID, metadata.CallGeneration, metadata.CallIncarnation = "ordinary-call", 1, uuid.New()
	client := NewClient(manager, config)
	require.NoError(t, client.Err())
	defer client.Stop()
	checkpoint, err := x2x3.ProductSequenceCheckpoint(template)
	require.NoError(t, err)
	permit, err := client.PrepareDeferredX3(xid, did, template, metadata, checkpoint.Context)
	require.NoError(t, err)
	require.Empty(t, client.preparedCalls)
	require.NoError(t, client.SendAcceptedX3WithSequence(permit, 1))
	require.Empty(t, client.acceptedCalls, "ordinary calls retain their existing live admission lifecycle, without durable closed-call records")
	require.Empty(t, client.closedCalls)
}

func TestDeferredX3RevocationAndReleaseRetainExistingBounds(t *testing.T) {
	config, manager, did, xid, metadata, template := x3ClientFixture(t)
	config.X3QueueSize = 1
	client := NewClient(manager, config)
	require.NoError(t, client.Err())
	defer client.Stop()
	checkpoint, err := x2x3.ProductSequenceCheckpoint(template)
	require.NoError(t, err)
	permit, err := client.PrepareDeferredX3(xid, did, template, metadata, checkpoint.Context)
	require.NoError(t, err)
	_, err = client.PrepareDeferredX3(xid, did, template, metadata, checkpoint.Context)
	require.ErrorIs(t, err, ErrQueueFull)
	permit.Release()
	permit, err = client.PrepareDeferredX3(xid, did, template, metadata, checkpoint.Context)
	require.NoError(t, err)
	client.CancelTask(xid, metadata.TaskGeneration)
	require.False(t, client.DeferredX3Eligible(permit))
	require.Error(t, client.SendAcceptedX3WithSequence(permit, 10))
	require.Zero(t, client.Stats().PhysicalQueueBytes)
	require.Zero(t, client.X3JournalStats().Persisted)
}

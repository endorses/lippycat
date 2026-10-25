//go:build tui || all

package tui

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type sshRemoteEventServer struct {
	data.UnimplementedDataServiceServer
	eventsv1.UnimplementedEventServiceServer
	batch  *eventsv1.ProtocolEventBatch
	legacy bool
}

func (s *sshRemoteEventServer) SubscribePackets(_ *data.SubscribeRequest, stream grpc.ServerStreamingServer[data.PacketBatch]) error {
	if err := stream.SendHeader(nil); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
func (s *sshRemoteEventServer) SubscribeEvents(_ *eventsv1.EventSubscribeRequest, stream grpc.ServerStreamingServer[eventsv1.EventSubscriptionMessage]) error {
	supported := protoadapter.SupportedKinds(true)
	if s.legacy {
		filtered := supported[:0]
		for _, kind := range supported {
			if kind != eventsv1.EventKind_EVENT_KIND_SSH {
				filtered = append(filtered, kind)
			}
		}
		supported = filtered
	}
	if err := stream.Send(&eventsv1.EventSubscriptionMessage{DeliverySequence: 1, Message: &eventsv1.EventSubscriptionMessage_Control{Control: &eventsv1.EventSubscriptionControl{Kind: eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED, StreamId: "ssh-ui-stream", DeliverySequence: 1, SupportedEventKinds: supported}}}); err != nil {
		return err
	}
	if !s.legacy {
		if err := stream.Send(&eventsv1.EventSubscriptionMessage{DeliverySequence: 2, Message: &eventsv1.EventSubscriptionMessage_Batch{Batch: s.batch}}); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func runtimeSSHRemoteBatch(t *testing.T) *eventsv1.ProtocolEventBatch {
	t.Helper()
	cfg := OfflineAnalysisConfig{Inputs: []string{writeSSHEventHistory(t, 1)}, EventCapacity: 8}
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 711, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	query, err := offline.AllEvents(context.Background(), session.EventDataset, offline.Token{Dataset: 711, Revision: offline.CompletedRevision, Query: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, query.Close()) }()
	batch := &eventsv1.ProtocolEventBatch{BatchSequence: 1, SemanticProfileRevision: 1}
	require.NoError(t, query.Iterate(context.Background(), func(record offline.EventRecord) error {
		if len(batch.Events) >= 64 {
			return errors.New("controlled SSH fixture exceeded bounded remote test batch")
		}
		wire, err := protoadapter.ToProto(record.Event)
		if err != nil {
			return err
		}
		if len(batch.Events) == 0 {
			batch.SourceNodeId = wire.Envelope.NodeId
			batch.ProducerSessionId = wire.Envelope.ProducerSessionId
			batch.FirstEventSequence = wire.EventSequence
		}
		batch.LastEventSequence = wire.EventSequence
		batch.Events = append(batch.Events, wire)
		return nil
	}))
	require.NoError(t, protoadapter.ValidateBatch(batch))
	return batch
}

func TestSSHRemoteTypedStreamReachesEventsAndReportsLegacyOmission(t *testing.T) {
	batch := runtimeSSHRemoteBatch(t)
	for _, legacy := range []bool{false, true} {
		name := "current"
		if legacy {
			name = "legacy-without-ssh"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			server := grpc.NewServer()
			source := &sshRemoteEventServer{batch: batch, legacy: legacy}
			data.RegisterDataServiceServer(server, source)
			eventsv1.RegisterEventServiceServer(server, source)
			served := make(chan error, 1)
			go func() { served <- server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				if err := <-served; err != nil {
					require.ErrorIs(t, err, grpc.ErrServerStopped)
				}
			})
			model := NewModel(64, 8, "", "", nil, false, true, "", false)
			t.Cleanup(model.Shutdown)
			model.uiState.Width, model.uiState.Height = 200, 36
			model.uiState.ViewMode = "events"
			handler := newRemoteTUIEventHandler(nil, model.pendingRemoteEvents)
			client, err := remotecapture.NewClientWithConfig(&remotecapture.ClientConfig{Address: listener.Addr().String()}, handler)
			require.NoError(t, err)
			t.Cleanup(client.Close)
			require.NoError(t, client.StreamPackets())
			var received bool
			require.Eventually(t, func() bool {
				batches := handler.DrainEventBatches()
				if len(batches) == 0 {
					return false
				}
				updated, _ := model.Update(EventBatchMsg{Batches: batches})
				model = updated.(Model)
				received = true
				return true
			}, 5*time.Second, time.Millisecond)
			require.True(t, received)
			if legacy {
				require.EqualValues(t, 1, model.eventStore.Stats().TransportLost)
				require.Empty(t, model.eventStore.Events())
				require.NoError(t, model.eventStore.AddUserFilter("kind:ssh"))
				require.Empty(t, model.eventStore.Events())
				return
			}
			require.Zero(t, model.eventStore.Stats().TransportLost)
			require.NoError(t, model.eventStore.AddUserFilter("kind:ssh AND status:complete AND role:client"))
			model.uiState.SelectedProtocol = components.Protocol{Name: "SSH", BPFFilter: "protocol:SSH"}
			model.syncEventsView()
			selected, ok := model.uiState.EventsView.DetailSelection()
			require.True(t, ok)
			event := selected.Event.(events.SSHEvent)
			require.Equal(t, events.SSHRoleClient, event.Role)
			require.Equal(t, "lippycat_fixture_client", event.SoftwareVersion)
			require.NotEmpty(t, event.HASSH)
			require.True(t, events.HasValidDeliveryIdentity(event.Envelope()))
			model.prepareEventsViewLayout()
			model.uiState.EventsView.PrepareDetails(180, 80)
			details := model.uiState.EventsView.RenderDetails(180, 80, true)
			require.Contains(t, details, event.HASSH)
			require.Contains(t, details, event.KEXAlgorithms)
			require.Contains(t, details, "tcp_syn")
			// The RPC preserves producer identity and exact ordered evidence.
			var wanted *eventsv1.ProtocolEvent
			for _, wire := range batch.Events {
				if wire.EventId == event.Envelope().EventID {
					wanted = wire
					break
				}
			}
			require.NotNil(t, wanted)
			decoded, omission, err := protoadapter.FromProto(wanted)
			require.NoError(t, err)
			require.Nil(t, omission)
			require.Equal(t, decoded, event)
			model.eventStore.ClearUserFilters()
			require.NoError(t, model.eventStore.AddUserFilter("kind:ssh AND status:complete AND role:server"))
			model.syncEventsView()
			serverItem, ok := model.uiState.EventsView.DetailSelection()
			require.True(t, ok)
			serverSSH := serverItem.Event.(events.SSHEvent)
			require.Equal(t, "lippycat_fixture_server", serverSSH.SoftwareVersion)
			require.NotEmpty(t, serverSSH.HASSH)
			require.NotEqual(t, event.HASSH, serverSSH.HASSH)
			model.uiState.EventsView.PrepareDetails(180, 80)
			require.Contains(t, model.uiState.EventsView.RenderDetails(180, 80, true), serverSSH.HASSH)
			model.eventStore.ClearUserFilters()
			require.NoError(t, model.eventStore.AddUserFilter("kind:ssh AND software_version:partial_ui AND status:partial"))
			model.syncEventsView()
			partialItem, ok := model.uiState.EventsView.DetailSelection()
			require.True(t, ok)
			partial := partialItem.Event.(events.SSHEvent)
			require.Empty(t, partial.HASSH)
			require.Equal(t, events.SSHReasonIncomplete, partial.Reason)
			model.uiState.EventsView.PrepareDetails(180, 80)
			require.Contains(t, model.uiState.EventsView.RenderDetails(180, 80, true), "Unavailable")
		})
	}
}

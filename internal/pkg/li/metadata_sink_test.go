//go:build li

package li

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type metadataTestSender struct {
	calls        int
	data         []byte
	xid          uuid.UUID
	destinations []uuid.UUID
}

func (s *metadataTestSender) SendX2(xid uuid.UUID, destinations []uuid.UUID, data []byte) error {
	s.calls++
	s.xid = xid
	s.destinations = append([]uuid.UUID(nil), destinations...)
	s.data = append([]byte(nil), data...)
	return nil
}

func metadataTestEnvelope() events.Envelope {
	return events.Envelope{Timestamp: time.Unix(42, 0), UID: "Ctest", NodeID: "hunter-a", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.10"), DestinationAddress: netip.MustParseAddr("198.51.100.20"), SourcePort: 50123, DestinationPort: 443}}
}

func activeMetadataManager(t *testing.T, target TargetIdentity, deliveryType DeliveryType) (*Manager, *InterceptTask) {
	t.Helper()
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.test", Port: 443, X2Enabled: true}))
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{target}, DestinationIDs: []uuid.UUID{did}, DeliveryType: deliveryType, Status: TaskStatusActive}
	require.NoError(t, m.ActivateTask(task))
	return m, task
}

func TestMetadataSinkDeliversAuthorizedHTTPWithoutHeaders(t *testing.T) {
	m, task := activeMetadataManager(t, TargetIdentity{Type: TargetTypeNAI, Value: "example.test"}, DeliveryX2Only)
	sender := &metadataTestSender{}
	sink, err := NewMetadataSink(MetadataSinkConfig{Enabled: true, Profile: InternetMetadataProfile, Manager: m, Sender: sender, NFID: "processor-a"})
	require.NoError(t, err)
	event := events.NewHTTPEvent(metadataTestEnvelope())
	event.Method, event.Host, event.URI = "GET", "example.test", "/private"
	event.Headers = map[string][]string{"authorization": {"secret"}}
	require.NoError(t, sink.HandleEvent(context.Background(), event))
	require.Equal(t, 1, sender.calls)
	assert.Equal(t, task.XID, sender.xid)

	var pdu x2x3.PDU
	require.NoError(t, pdu.UnmarshalBinary(sender.data))
	assert.Equal(t, x2x3.PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, x2x3.PayloadFormatProprietary, pdu.Header.PayloadFormat)
	assert.Equal(t, x2x3.PayloadDirectionUnknown, pdu.Header.PayloadDirection)
	var payload struct {
		Profile  string      `json:"profile"`
		Kind     events.Kind `json:"kind"`
		Metadata struct {
			Headers map[string][]string `json:"Headers"`
			Method  string              `json:"Method"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(pdu.Payload, &payload))
	assert.Equal(t, InternetMetadataProfile, payload.Profile)
	assert.Equal(t, events.KindHTTP, payload.Kind)
	assert.Equal(t, "GET", payload.Metadata.Method)
	assert.Nil(t, payload.Metadata.Headers)
	assert.Equal(t, uint64(1), sink.Stats().Delivered)
}

func TestMetadataSinkRequiresX2TaskAndTargetMatch(t *testing.T) {
	m, _ := activeMetadataManager(t, TargetIdentity{Type: TargetTypeNAI, Value: "nomatch.example"}, DeliveryX3Only)
	sender := &metadataTestSender{}
	sink, err := NewMetadataSink(MetadataSinkConfig{Enabled: true, Manager: m, Sender: sender})
	require.NoError(t, err)
	event := events.NewDNSEvent(metadataTestEnvelope())
	event.Query = "example.test"
	require.NoError(t, sink.HandleEvent(context.Background(), event))
	assert.Zero(t, sender.calls)
	assert.Equal(t, uint64(1), sink.Stats().Skipped)
}

func TestMetadataSinkRejectsContentAndGatesFileMetadata(t *testing.T) {
	m, _ := activeMetadataManager(t, TargetIdentity{Type: TargetTypeNAI, Value: "example.test"}, DeliveryX2Only)
	sender := &metadataTestSender{}
	sink, err := NewMetadataSink(MetadataSinkConfig{Enabled: true, Manager: m, Sender: sender})
	require.NoError(t, err)
	content := events.NewFileContentEvent(metadataTestEnvelope())
	content.Content = []byte("secret")
	assert.ErrorIs(t, sink.HandleEvent(context.Background(), content), ErrMetadataContentRejected)
	metadata := events.NewFileMetadataEvent(metadataTestEnvelope())
	metadata.Filename = "report.pdf"
	require.NoError(t, sink.HandleEvent(context.Background(), metadata))
	assert.Zero(t, sender.calls)
	assert.Equal(t, uint64(1), sink.Stats().Rejected)
}

func TestNewMetadataSinkRejectsUnknownProfile(t *testing.T) {
	_, err := NewMetadataSink(MetadataSinkConfig{Profile: "everything"})
	assert.ErrorIs(t, err, ErrUnknownMetadataProfile)
}

package upstream

import (
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNetworkRequiredVersusSupportedKinds(t *testing.T) {
	old := &management.ProcessorRegistrationResponse{AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: []int32{1, 2, 3, 4, 5, 6, 7}}
	require.NoError(t, validateAcceptedEventProfile(old))
	require.ErrorContains(t, validateAcceptedEventProfile(old, eventsv1.EventKind_EVENT_KIND_DHCP), "kind 8")
	old.AcceptedEventKinds = append(old.AcceptedEventKinds, 8)
	require.NoError(t, validateAcceptedEventProfile(old, eventsv1.EventKind_EVENT_KIND_DHCP))
}

func TestInventoryProductionFeatureRequiresPolicyOrEnforcedConsumer(t *testing.T) {
	m := NewManager(Config{}, nil)
	require.NotContains(t, m.eventAnalysisFeatures(), "inventory_production")
	m.config.InventoryEnabled = true
	require.Contains(t, m.eventAnalysisFeatures(), "inventory_production")
	m.config.InventoryEnabled = false
	m.config.RequiredEventKinds = []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_KNOWN_HOST}
	require.Contains(t, m.eventAnalysisFeatures(), "inventory_production")
	m.config.RequiredEventKinds = []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DHCP}
	require.NotContains(t, m.eventAnalysisFeatures(), "inventory_production")
}

func TestInventoryPromiseKeepsOptionalKindsOptionalUpstream(t *testing.T) {
	old := &management.ProcessorRegistrationResponse{AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: []int32{1, 2, 3, 4, 5, 6, 7}}
	producer := NewManager(Config{ForwardMode: "events", InventoryEnabled: true}, nil)
	defer producer.Disconnect()
	require.Empty(t, producer.config.RequiredEventKinds)
	require.Contains(t, producer.eventAnalysisFeatures(), "inventory_production")
	require.NoError(t, validateAcceptedEventProfile(old, producer.config.RequiredEventKinds...))
	sourceRequirements := RequiredInventoryKinds(producer.config.RequiredEventKinds, producer.config.InventoryEnabled)
	require.Contains(t, sourceRequirements, eventsv1.EventKind_EVENT_KIND_KNOWN_HOST)
	require.Contains(t, sourceRequirements, eventsv1.EventKind_EVENT_KIND_KNOWN_SERVICE)
	consumer := NewManager(Config{ForwardMode: "events", RequiredEventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_KNOWN_HOST}}, nil)
	defer consumer.Disconnect()
	require.Equal(t, []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_KNOWN_HOST}, consumer.config.RequiredEventKinds)
	require.ErrorContains(t, validateAcceptedEventProfile(old, consumer.config.RequiredEventKinds...), "kind 10")
	old.AcceptedEventKinds = append(old.AcceptedEventKinds, 10)
	require.NoError(t, validateAcceptedEventProfile(old, consumer.config.RequiredEventKinds...))
	require.Len(t, RequiredInventoryKinds(consumer.config.RequiredEventKinds, false), 2)
	optional := NewManager(Config{ForwardMode: "events"}, nil)
	defer optional.Disconnect()
	require.Empty(t, RequiredInventoryKinds(optional.config.RequiredEventKinds, false))
}

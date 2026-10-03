package protoadapter

import (
	"fmt"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
)

// InventoryProductionFeature distinguishes configured inventory production
// (or a relay enforcing equivalent source requirements) from codec support.
const InventoryProductionFeature = "inventory_production"

// This additive mapping is independent of the semantic profile. Support is not
// a promise that a particular source has enabled inventory production.
var kindMappings = []struct {
	native    events.Kind
	wire      eventsv1.EventKind
	stream    string
	inventory bool
}{
	{events.KindConn, eventsv1.EventKind_EVENT_KIND_CONN, "conn", false},
	{events.KindDNS, eventsv1.EventKind_EVENT_KIND_DNS, "dns", false},
	{events.KindTLS, eventsv1.EventKind_EVENT_KIND_TLS, "ssl", false},
	{events.KindHTTP, eventsv1.EventKind_EVENT_KIND_HTTP, "http", false},
	{events.KindSMTP, eventsv1.EventKind_EVENT_KIND_SMTP, "smtp", false},
	{events.KindFileMetadata, eventsv1.EventKind_EVENT_KIND_FILE_METADATA, "files", false},
	{events.KindRADIUS, eventsv1.EventKind_EVENT_KIND_RADIUS, "radius", false},
	{events.KindDHCP, eventsv1.EventKind_EVENT_KIND_DHCP, "dhcp", false},
	{events.KindNTP, eventsv1.EventKind_EVENT_KIND_NTP, "ntp", false},
	{events.KindKnownHost, eventsv1.EventKind_EVENT_KIND_KNOWN_HOST, "known_hosts", true},
	{events.KindKnownService, eventsv1.EventKind_EVENT_KIND_KNOWN_SERVICE, "known_services", true},
}

func WireKind(kind events.Kind) (eventsv1.EventKind, bool) {
	for _, m := range kindMappings {
		if m.native == kind {
			return m.wire, true
		}
	}
	return 0, false
}
func NativeKind(kind eventsv1.EventKind) (events.Kind, bool) {
	for _, m := range kindMappings {
		if m.wire == kind {
			return m.native, true
		}
	}
	return "", false
}
func KindForStream(stream string) (events.Kind, bool) {
	for _, m := range kindMappings {
		if m.stream == stream {
			return m.native, true
		}
	}
	return "", false
}
func StreamForKind(kind events.Kind) (string, bool) {
	for _, m := range kindMappings {
		if m.native == kind {
			return m.stream, true
		}
	}
	return "", false
}

// SupportedKinds lists available encodings or enabled production kinds. Pass
// true for a relay's encoding support; producers must use their enabled policy.
func SupportedKinds(includeInventory bool) []eventsv1.EventKind {
	var kinds []eventsv1.EventKind
	for _, m := range kindMappings {
		if !m.inventory || includeInventory {
			kinds = append(kinds, m.wire)
		}
	}
	return kinds
}
func SupportedKindIDs(includeInventory bool) []int32 {
	var ids []int32
	for _, k := range SupportedKinds(includeInventory) {
		ids = append(ids, int32(k))
	}
	return ids
}

// RequiredKinds returns only configured stream requirements, in canonical
// order. It intentionally does not require every supported optional kind.
func RequiredKinds(streams []string) ([]eventsv1.EventKind, error) {
	selected := make(map[events.Kind]bool, len(streams))
	for _, stream := range streams {
		kind, ok := KindForStream(stream)
		if !ok {
			return nil, fmt.Errorf("unknown log stream %q", stream)
		}
		selected[kind] = true
	}
	var result []eventsv1.EventKind
	for _, m := range kindMappings {
		if selected[m.native] {
			result = append(result, m.wire)
		}
	}
	return result, nil
}

package statusclient

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/output"
)

// StatusJSON represents processor status in JSON-friendly format
type StatusJSON struct {
	ProcessorID       string `json:"processor_id"`
	Status            string `json:"status"`
	TotalHunters      uint32 `json:"total_hunters"`
	HealthyHunters    uint32 `json:"healthy_hunters"`
	WarningHunters    uint32 `json:"warning_hunters"`
	ErrorHunters      uint32 `json:"error_hunters"`
	TotalPackets      uint64 `json:"total_packets_received"`
	PacketsForwarded  uint64 `json:"total_packets_forwarded"`
	TotalFilters      uint32 `json:"total_filters"`
	UpstreamProcessor string `json:"upstream_processor,omitempty"`
}

// HunterJSON represents a connected hunter in JSON-friendly format
type HunterJSON struct {
	HunterID          string            `json:"hunter_id"`
	Hostname          string            `json:"hostname"`
	RemoteAddr        string            `json:"remote_addr"`
	Status            string            `json:"status"`
	ConnectedDuration uint64            `json:"connected_duration_sec"`
	Interfaces        []string          `json:"interfaces"`
	Stats             *HunterStatsJSON  `json:"stats"`
	Capabilities      *CapabilitiesJSON `json:"capabilities,omitempty"`
}

// HunterStatsJSON represents hunter statistics in JSON-friendly format
type HunterStatsJSON struct {
	PacketsCaptured  uint64 `json:"packets_captured"`
	PacketsMatched   uint64 `json:"packets_matched"`
	PacketsForwarded uint64 `json:"packets_forwarded"`
	PacketsDropped   uint64 `json:"packets_dropped"`
	BufferBytes      uint64 `json:"buffer_bytes"`
	ActiveFilters    uint32 `json:"active_filters"`
}

// CapabilitiesJSON represents hunter capabilities in JSON-friendly format
type CapabilitiesJSON struct {
	FilterTypes     []string `json:"filter_types,omitempty"`
	MaxBufferSize   uint64   `json:"max_buffer_size,omitempty"`
	GPUAcceleration bool     `json:"gpu_acceleration"`
	AFXDP           bool     `json:"af_xdp"`
}

// TopologyNodeJSON represents a processor node in the topology
type TopologyNodeJSON struct {
	ProcessorID          string              `json:"processor_id"`
	Address              string              `json:"address"`
	Status               string              `json:"status"`
	UpstreamProcessor    string              `json:"upstream_processor,omitempty"`
	HierarchyDepth       uint32              `json:"hierarchy_depth"`
	Reachable            bool                `json:"reachable"`
	UnreachableReason    string              `json:"unreachable_reason,omitempty"`
	Hunters              []*HunterJSON       `json:"hunters,omitempty"`
	DownstreamProcessors []*TopologyNodeJSON `json:"downstream_processors,omitempty"`
}

// StatusResponseToJSON converts a StatusResponse to JSON bytes.
// When pretty is true, output is indented; when false, output is compact.
func StatusResponseToJSON(resp *management.StatusResponse, pretty bool) ([]byte, error) {
	status := &StatusJSON{}

	if resp.ProcessorStats != nil {
		status.ProcessorID = resp.ProcessorStats.ProcessorId
		status.Status = processorStatusToString(resp.ProcessorStats.Status)
		status.TotalHunters = resp.ProcessorStats.TotalHunters
		status.HealthyHunters = resp.ProcessorStats.HealthyHunters
		status.WarningHunters = resp.ProcessorStats.WarningHunters
		status.ErrorHunters = resp.ProcessorStats.ErrorHunters
		status.TotalPackets = resp.ProcessorStats.TotalPacketsReceived
		status.PacketsForwarded = resp.ProcessorStats.TotalPacketsForwarded
		status.TotalFilters = resp.ProcessorStats.TotalFilters
		status.UpstreamProcessor = resp.ProcessorStats.UpstreamProcessor
	}

	return output.MarshalJSONPretty(status, pretty)
}

// HuntersToJSON converts a slice of ConnectedHunter to JSON bytes.
// When pretty is true, output is indented; when false, output is compact.
func HuntersToJSON(hunters []*management.ConnectedHunter, pretty bool) ([]byte, error) {
	result := make([]*HunterJSON, len(hunters))
	for i, h := range hunters {
		result[i] = hunterToJSON(h)
	}
	return output.MarshalJSONPretty(result, pretty)
}

// HunterToJSON converts a single ConnectedHunter to JSON bytes.
// When pretty is true, output is indented; when false, output is compact.
func HunterToJSON(hunter *management.ConnectedHunter, pretty bool) ([]byte, error) {
	return output.MarshalJSONPretty(hunterToJSON(hunter), pretty)
}

// TopologyToJSON converts a TopologyResponse to JSON bytes.
// When pretty is true, output is indented; when false, output is compact.
func TopologyToJSON(resp *management.TopologyResponse, pretty bool) ([]byte, error) {
	if resp.Processor == nil {
		return output.MarshalJSONPretty(nil, pretty)
	}
	node := processorNodeToJSON(resp.Processor)
	return output.MarshalJSONPretty(node, pretty)
}

func hunterToJSON(h *management.ConnectedHunter) *HunterJSON {
	hunter := &HunterJSON{
		HunterID:          h.HunterId,
		Hostname:          h.Hostname,
		RemoteAddr:        h.RemoteAddr,
		Status:            hunterStatusToString(h.Status),
		ConnectedDuration: h.ConnectedDurationSec,
		Interfaces:        h.Interfaces,
	}

	if h.Stats != nil {
		hunter.Stats = &HunterStatsJSON{
			PacketsCaptured:  h.Stats.PacketsCaptured,
			PacketsMatched:   h.Stats.PacketsMatched,
			PacketsForwarded: h.Stats.PacketsForwarded,
			PacketsDropped:   h.Stats.PacketsDropped,
			BufferBytes:      h.Stats.BufferBytes,
			ActiveFilters:    h.Stats.ActiveFilters,
		}
	}

	if h.Capabilities != nil {
		hunter.Capabilities = &CapabilitiesJSON{
			FilterTypes:     h.Capabilities.FilterTypes,
			MaxBufferSize:   h.Capabilities.MaxBufferSize,
			GPUAcceleration: h.Capabilities.GpuAcceleration,
			AFXDP:           h.Capabilities.AfXdp,
		}
	}

	return hunter
}

func processorNodeToJSON(node *management.ProcessorNode) *TopologyNodeJSON {
	result := &TopologyNodeJSON{
		ProcessorID:       node.ProcessorId,
		Address:           node.Address,
		Status:            processorStatusToString(node.Status),
		UpstreamProcessor: node.UpstreamProcessor,
		HierarchyDepth:    node.HierarchyDepth,
		Reachable:         node.Reachable,
		UnreachableReason: node.UnreachableReason,
	}

	if len(node.Hunters) > 0 {
		result.Hunters = make([]*HunterJSON, len(node.Hunters))
		for i, h := range node.Hunters {
			result.Hunters[i] = hunterToJSON(h)
		}
	}

	if len(node.DownstreamProcessors) > 0 {
		result.DownstreamProcessors = make([]*TopologyNodeJSON, len(node.DownstreamProcessors))
		for i, p := range node.DownstreamProcessors {
			result.DownstreamProcessors[i] = processorNodeToJSON(p)
		}
	}

	return result
}

func hunterStatusToString(status management.HunterStatus) string {
	switch status {
	case management.HunterStatus_STATUS_HEALTHY:
		return "healthy"
	case management.HunterStatus_STATUS_WARNING:
		return "warning"
	case management.HunterStatus_STATUS_ERROR:
		return "error"
	case management.HunterStatus_STATUS_STOPPING:
		return "stopping"
	default:
		return "unknown"
	}
}

func processorStatusToString(status management.ProcessorStatus) string {
	switch status {
	case management.ProcessorStatus_PROCESSOR_HEALTHY:
		return "healthy"
	case management.ProcessorStatus_PROCESSOR_WARNING:
		return "warning"
	case management.ProcessorStatus_PROCESSOR_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

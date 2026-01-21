//go:build processor || tap || all

// Package processor - gRPC Service Handlers
//
// This file contains all gRPC service method implementations for the processor:
//
// Data Service (3 methods):
//   - StreamPackets()              - Hunter packet ingestion (bidirectional streaming)
//   - SubscribePackets()           - TUI client packet subscription (server streaming)
//   - SubscribeCorrelatedCalls()   - B2BUA call correlation updates (server streaming)
//
// Management Service - Hunter Management (4 methods):
//   - RegisterHunter()             - Hunter registration with processor
//   - Heartbeat()                  - Hunter heartbeat and keepalive
//   - GetHunterStatus()            - Query hunter connection status
//   - ListAvailableHunters()       - List all connected hunters
//
// Management Service - Filter Management (7 methods):
//   - GetFilters()                 - Get current processor filters
//   - SubscribeFilters()           - Subscribe to filter updates
//   - UpdateFilter()               - Update a filter
//   - DeleteFilter()               - Delete a filter
//   - UpdateFilterOnProcessor()    - Propagate filter update to processor hierarchy
//   - DeleteFilterOnProcessor()    - Propagate filter deletion to processor hierarchy
//   - GetFiltersFromProcessor()    - Query filters from processor hierarchy
//
// Management Service - Processor Hierarchy (4 methods):
//   - RegisterProcessor()          - Register downstream processor
//   - GetTopology()                - Get processor hierarchy topology
//   - SubscribeTopology()          - Subscribe to topology updates
//   - RequestAuthToken()           - Request authentication token for proxy mode
//
// Helper Functions:
//   - buildTLSCredentials()        - Build gRPC TLS credentials from config
//   - convertChainErrorToStatus()  - Convert proxy chain errors to gRPC status
//   - correlatedCallToProto()      - Convert internal B2BUA call to protobuf
//   - Audit logging helpers        - Log management operations for security audit trail
package processor

import (
	"context"
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/proxy"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// StreamPackets handles packet streaming from hunters (Data Service)
func (p *Processor) StreamPackets(stream data.DataService_StreamPacketsServer) error {
	var hunterID string // Track which hunter this stream belongs to

	defer func() {
		if hunterID != "" {
			logger.Info("Packet stream closed", "hunter_id", hunterID)
		}
	}()

	for {
		batch, err := stream.Recv()
		if err != nil {
			logger.Debug("Stream ended", "error", err, "hunter_id", hunterID)
			return err
		}

		// Track hunter ID from first batch
		if hunterID == "" {
			hunterID = batch.HunterId
			logger.Info("Packet stream started", "hunter_id", hunterID)
		}

		// Convert protobuf batch to internal format and process
		internalBatch := source.FromProtoBatch(batch)
		p.processBatch(internalBatch)

		// Determine flow control state based on processor load
		flowControl := p.flowController.Determine()

		// Send acknowledgment with flow control signal
		ack := &data.StreamControl{
			AckSequence: batch.Sequence,
			FlowControl: flowControl,
		}

		if err := stream.Send(ack); err != nil {
			// Log error but don't close stream - hunter may recover
			// Closing stream would disconnect the hunter unnecessarily
			logger.Warn("Failed to send flow control acknowledgment, continuing",
				"error", err,
				"sequence", batch.Sequence,
				"hunter_id", batch.HunterId)
			// Continue processing - don't return error
		}
	}
}

// RegisterHunter registers a hunter node with the processor (Management Service).
//
// SECURITY NOTE: Hunter authentication relies on the gRPC server's TLS configuration.
//   - When TLSClientAuth=true (mutual TLS): Hunters must present valid client certificates.
//     This provides strong authentication and is REQUIRED for production deployments.
//   - When TLSClientAuth=false: Any network client can register as a hunter with any ID.
//     This is INSECURE - malicious clients can impersonate legitimate hunters.
//   - When TLSEnabled=false: All traffic is unencrypted and unauthenticated (CRITICAL risk).
//
// For production deployments, set LIPPYCAT_PRODUCTION=true to enforce mutual TLS.
func (p *Processor) RegisterHunter(ctx context.Context, req *management.HunterRegistration) (*management.RegistrationResponse, error) {
	hunterID := req.HunterId

	logger.Info("Hunter registration request",
		"hunter_id", hunterID,
		"hostname", req.Hostname,
		"interfaces", req.Interfaces,
		"capabilities", req.Capabilities)

	// Register hunter with manager
	_, isReconnect, err := p.hunterManager.Register(hunterID, req.Hostname, req.Interfaces, req.Capabilities)
	if err != nil {
		if err == hunter.ErrMaxHuntersReached {
			logger.Warn("Max hunters limit reached", "limit", p.config.MaxHunters)
			return nil, status.Errorf(codes.ResourceExhausted,
				"maximum number of hunters reached: limit %d", p.config.MaxHunters)
		}
		return nil, status.Errorf(codes.Internal, "failed to register hunter: %v", err)
	}

	logger.Info("Hunter registered successfully", "hunter_id", hunterID, "reconnect", isReconnect)

	// Get applicable filters for this hunter
	filters := p.filterManager.GetForHunter(hunterID)

	return &management.RegistrationResponse{
		Accepted:   true,
		AssignedId: hunterID,
		Filters:    filters,
		Config: &management.ProcessorConfig{
			BatchSize:            64,
			BatchTimeoutMs:       constants.ProcessorBatchTimeoutMs,
			ReconnectIntervalSec: 5,
			MaxReconnectAttempts: 0, // infinite
			ProcessorId:          p.config.ProcessorID,
		},
	}, nil
}

// Heartbeat handles bidirectional heartbeat stream (Management Service)
func (p *Processor) Heartbeat(stream management.ManagementService_HeartbeatServer) error {
	logger.Debug("New heartbeat stream")

	for {
		hb, err := stream.Recv()
		if err != nil {
			logger.Debug("Heartbeat stream ended", "error", err)
			return err
		}

		hunterID := hb.HunterId

		// Update hunter status and stats
		statsChanged := p.hunterManager.UpdateHeartbeat(hunterID, hb.TimestampNs, hb.Status, hb.Stats)

		// Log heartbeat with stats (DEBUG level for normal operation, WARN if missing)
		if hb.Stats != nil {
			logger.Debug("Heartbeat received with stats",
				"hunter_id", hunterID,
				"active_filters", hb.Stats.ActiveFilters,
				"packets_captured", hb.Stats.PacketsCaptured,
				"packets_forwarded", hb.Stats.PacketsForwarded,
				"stats_changed", statsChanged)
		} else {
			logger.Warn("Heartbeat received WITHOUT stats (proto3 issue?)",
				"hunter_id", hunterID,
				"timestamp_ns", hb.TimestampNs,
				"status", hb.Status)
		}

		// Send response
		processorStats := p.statsCollector.GetProto()
		resp := &management.ProcessorHeartbeat{
			TimestampNs:      hb.TimestampNs,
			Status:           management.ProcessorStatus_PROCESSOR_HEALTHY,
			HuntersConnected: processorStats.TotalHunters,
			ProcessorId:      p.config.ProcessorID,
		}

		if err := stream.Send(resp); err != nil {
			logger.Error("Failed to send heartbeat response", "error", err)
			return err
		}
	}
}

// GetFilters retrieves filters for a hunter (Management Service)
// If hunter_id is empty, returns all filters (for CLI/administrative use).
// If hunter_id is specified, returns only filters applicable to that hunter
// after filtering by target hunters and capability compatibility.
func (p *Processor) GetFilters(ctx context.Context, req *management.FilterRequest) (*management.FilterResponse, error) {
	var filters []*management.Filter
	if req.HunterId == "" {
		// Return all filters for CLI/administrative queries
		filters = p.filterManager.GetAll()
	} else {
		// Return filters filtered by hunter capabilities and targeting
		filters = p.filterManager.GetForHunter(req.HunterId)
	}

	return &management.FilterResponse{
		Filters: filters,
	}, nil
}

// SubscribeFilters streams filter updates to hunters (Management Service)
func (p *Processor) SubscribeFilters(req *management.FilterRequest, stream management.ManagementService_SubscribeFiltersServer) error {
	hunterID := req.HunterId
	logger.Debug("SubscribeFilters called", "hunter_id", hunterID, "stream_context", stream.Context().Err())
	logger.Info("Filter subscription started", "hunter_id", hunterID)

	// Create filter update channel for this hunter
	filterChan := p.filterManager.AddChannel(hunterID)

	// Cleanup on disconnect
	defer func() {
		p.filterManager.RemoveChannel(hunterID)
		logger.Debug("SubscribeFilters exiting", "hunter_id", hunterID, "stream_context", stream.Context().Err())
		logger.Info("Filter subscription ended", "hunter_id", hunterID)
	}()

	// Send current filters immediately
	currentFilters := p.filterManager.GetForHunter(hunterID)
	for _, filter := range currentFilters {
		update := &management.FilterUpdate{
			UpdateType: management.FilterUpdateType_UPDATE_ADD,
			Filter:     filter,
		}
		if err := stream.Send(update); err != nil {
			logger.Error("Failed to send initial filter", "error", err, "filter_id", filter.Id)
			return err
		}
	}

	logger.Info("Sent initial filters", "hunter_id", hunterID, "count", len(currentFilters))

	// Stream filter updates
	for {
		select {
		case <-stream.Context().Done():
			logger.Debug("SubscribeFilters: stream context cancelled", "hunter_id", hunterID, "error", stream.Context().Err())
			return nil
		case update, ok := <-filterChan:
			if !ok {
				logger.Debug("SubscribeFilters: filter channel closed", "hunter_id", hunterID)
				return nil
			}

			logger.Debug("Sending filter update",
				"hunter_id", hunterID,
				"update_type", update.UpdateType,
				"filter_id", update.Filter.Id)

			if err := stream.Send(update); err != nil {
				logger.Error("Failed to send filter update", "hunter_id", hunterID, "error", err)
				return err
			}
			logger.Debug("Filter update sent successfully", "hunter_id", hunterID, "update_type", update.UpdateType)
		}
	}
}

// GetHunterStatus retrieves status of connected hunters (Management Service)
// This includes hunters from this processor AND all downstream processors in the hierarchy.
func (p *Processor) GetHunterStatus(ctx context.Context, req *management.StatusRequest) (*management.StatusResponse, error) {
	hunters := p.hunterManager.GetAll(req.HunterId)

	connectedHunters := make([]*management.ConnectedHunter, 0, len(hunters))
	for _, h := range hunters {
		// Calculate connection duration (safe: duration won't overflow, max ~292 years)
		durationNs := time.Now().UnixNano() - h.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		connectedHunters = append(connectedHunters, &management.ConnectedHunter{
			HunterId:             h.ID,
			Hostname:             h.Hostname,
			RemoteAddr:           h.RemoteAddr,
			Status:               h.Status,
			ConnectedDurationSec: durationSec,
			LastHeartbeatNs:      h.LastHeartbeat,
			Stats: &management.HunterStats{
				PacketsCaptured:  h.PacketsCaptured,  // From hunter's heartbeat stats
				PacketsForwarded: h.PacketsForwarded, // From hunter's heartbeat stats
				ActiveFilters:    h.ActiveFilters,
				CpuPercent:       h.CpuPercent,
				MemoryRssBytes:   h.MemoryRssBytes,
				MemoryLimitBytes: h.MemoryLimitBytes,
			},
			Interfaces:   h.Interfaces,
			Capabilities: h.Capabilities, // Hunter capabilities (filter types, etc.)
		})
	}

	// Inject virtual hunter for TAP nodes (local capture)
	// Only include if no specific hunter ID filter, or filter matches virtual hunter
	if virtualHunter := p.SynthesizeVirtualHunter(); virtualHunter != nil {
		if req.HunterId == "" || req.HunterId == virtualHunter.HunterId {
			// Prepend virtual hunter so it appears first
			connectedHunters = append([]*management.ConnectedHunter{virtualHunter}, connectedHunters...)
		}
	}

	// Query downstream processors for their hunters (aggregates the full hierarchy)
	if p.downstreamManager != nil {
		downstreams := p.downstreamManager.GetAll()
		for _, downstream := range downstreams {
			if downstream.Client == nil {
				continue
			}

			// Use short timeout to avoid blocking on slow/unavailable downstream
			queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			resp, err := downstream.Client.GetHunterStatus(queryCtx, &management.StatusRequest{
				HunterId: req.HunterId, // Pass through any filter
			})
			cancel()

			if err != nil {
				logger.Debug("Failed to query downstream processor for hunter status",
					"downstream_id", downstream.ProcessorID,
					"error", err)
				continue
			}

			// Append downstream hunters to our response
			connectedHunters = append(connectedHunters, resp.Hunters...)
		}
	}

	processorStats := p.statsCollector.GetProto()

	return &management.StatusResponse{
		Hunters:        connectedHunters,
		ProcessorStats: processorStats,
	}, nil
}

// ListAvailableHunters returns list of all hunters connected to this processor (for TUI hunter selection)
func (p *Processor) ListAvailableHunters(ctx context.Context, req *management.ListHuntersRequest) (*management.ListHuntersResponse, error) {
	hunters := p.hunterManager.GetAll("")

	availableHunters := make([]*management.AvailableHunter, 0, len(hunters))
	for _, h := range hunters {
		// Calculate connection duration (safe: duration won't overflow, max ~292 years)
		durationNs := time.Now().UnixNano() - h.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		availableHunters = append(availableHunters, &management.AvailableHunter{
			HunterId:             h.ID,
			Hostname:             h.Hostname,
			Interfaces:           h.Interfaces,
			Status:               h.Status,
			RemoteAddr:           h.RemoteAddr,
			ConnectedDurationSec: durationSec,
			Capabilities:         h.Capabilities, // Hunter capabilities (filter types, etc.)
		})
	}

	// Inject virtual hunter for TAP nodes (local capture)
	if virtualHunter := p.SynthesizeVirtualHunter(); virtualHunter != nil {
		// Prepend virtual hunter so it appears first
		availableHunters = append([]*management.AvailableHunter{{
			HunterId:             virtualHunter.HunterId,
			Hostname:             virtualHunter.Hostname,
			Interfaces:           virtualHunter.Interfaces,
			Status:               virtualHunter.Status,
			RemoteAddr:           "", // Local capture has no remote address
			ConnectedDurationSec: virtualHunter.ConnectedDurationSec,
			Capabilities:         virtualHunter.Capabilities,
		}}, availableHunters...)
	}

	logger.Debug("ListAvailableHunters request", "hunter_count", len(availableHunters))

	return &management.ListHuntersResponse{
		Hunters: availableHunters,
	}, nil
}

// RegisterProcessor registers a downstream processor that forwards packets to this processor
func (p *Processor) RegisterProcessor(ctx context.Context, req *management.ProcessorRegistration) (*management.ProcessorRegistrationResponse, error) {
	logger.Info("Downstream processor registration",
		"processor_id", req.ProcessorId,
		"listen_address", req.ListenAddress,
		"version", req.Version)

	// Calculate hierarchy depth from upstream chain
	// Depth = len(upstream_chain) + 1 (since this processor adds one more level)
	// Example: upstream_chain = ["root"] means registering processor is at depth 1
	// Example: upstream_chain = ["root", "intermediate"] means registering processor is at depth 2
	hierarchyDepth := len(req.UpstreamChain) + 1

	// Check if hierarchy depth exceeds maximum
	if hierarchyDepth > constants.MaxHierarchyDepth {
		errMsg := fmt.Sprintf("hierarchy depth %d exceeds maximum allowed depth %d", hierarchyDepth, constants.MaxHierarchyDepth)
		logger.Warn("Rejecting processor registration: depth limit exceeded",
			"processor_id", req.ProcessorId,
			"hierarchy_depth", hierarchyDepth,
			"max_depth", constants.MaxHierarchyDepth)
		return &management.ProcessorRegistrationResponse{
			Accepted: false,
			Error:    errMsg,
		}, nil
	}

	// Check for cycles in the upstream chain
	// A cycle occurs if this processor's ID appears in the registering processor's upstream chain
	// Example: A → B → C → A (cycle) - when A tries to register with C,
	// C's ID would already be in A's upstream chain
	for _, upstreamID := range req.UpstreamChain {
		if upstreamID == p.config.ProcessorID {
			errMsg := fmt.Sprintf("cycle detected: processor %s is already in the upstream chain %v",
				p.config.ProcessorID, req.UpstreamChain)
			logger.Warn("Rejecting processor registration: cycle detected",
				"processor_id", req.ProcessorId,
				"this_processor_id", p.config.ProcessorID,
				"upstream_chain", req.UpstreamChain)
			return &management.ProcessorRegistrationResponse{
				Accepted: false,
				Error:    errMsg,
			}, nil
		}
	}

	err := p.downstreamManager.Register(req.ProcessorId, req.ListenAddress, req.Version)
	if err != nil {
		return &management.ProcessorRegistrationResponse{
			Accepted: false,
			Error:    err.Error(),
		}, nil
	}

	// Add processor to proxy manager's topology cache for routing
	processorNode := &proxy.ProcessorNode{
		ID:             req.ProcessorId,
		Address:        req.ListenAddress,
		ParentID:       p.config.ProcessorID, // This processor is the parent
		HierarchyDepth: int32(hierarchyDepth),
		Reachable:      true,
		Metadata: map[string]string{
			"version": req.Version,
		},
	}
	p.proxyManager.AddProcessor(processorNode)

	logger.Debug("Publishing PROCESSOR_CONNECTED topology event",
		"processor_id", req.ProcessorId,
		"listen_address", req.ListenAddress)

	// Query the downstream's topology to get its hunters (including virtual hunter for TAPs)
	// This is done after registration so we have a client connection to the downstream
	var hunters []*management.ConnectedHunter
	if downstream := p.downstreamManager.Get(req.ProcessorId); downstream != nil && downstream.Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := downstream.Client.GetTopology(ctx, &management.TopologyRequest{})
		cancel()
		if err == nil && resp.Processor != nil {
			hunters = resp.Processor.Hunters
			logger.Debug("Retrieved hunters from downstream processor",
				"processor_id", req.ProcessorId,
				"hunter_count", len(hunters))
		} else if err != nil {
			logger.Debug("Could not query downstream topology for hunters",
				"processor_id", req.ProcessorId,
				"error", err)
		}
	}

	// Publish topology update event so upstream processors learn about this new processor
	topologyUpdate := &management.TopologyUpdate{
		UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		ProcessorId: p.config.ProcessorID, // The processor where this event occurred
		TimestampNs: time.Now().UnixNano(),
		Event: &management.TopologyUpdate_ProcessorConnected{
			ProcessorConnected: &management.ProcessorConnectedEvent{
				Processor: &management.ProcessorNode{
					ProcessorId:       req.ProcessorId,
					Address:           req.ListenAddress,
					Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
					UpstreamProcessor: p.config.ProcessorID,
					HierarchyDepth:    uint32(hierarchyDepth),
					Reachable:         true,
					Hunters:           hunters,
				},
			},
		},
	}
	p.proxyManager.PublishTopologyUpdate(topologyUpdate)

	return &management.ProcessorRegistrationResponse{
		Accepted:            true,
		UpstreamProcessorId: p.config.ProcessorID,
	}, nil
}

// GetTopology returns the complete downstream topology (processors and hunters)
func (p *Processor) GetTopology(ctx context.Context, req *management.TopologyRequest) (*management.TopologyResponse, error) {
	logger.Debug("GetTopology request")

	// Get hunters for this processor
	hunters := p.hunterManager.GetAll("")
	connectedHunters := make([]*management.ConnectedHunter, 0, len(hunters))
	for _, h := range hunters {
		durationNs := time.Now().UnixNano() - h.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		connectedHunters = append(connectedHunters, &management.ConnectedHunter{
			HunterId:             h.ID,
			Hostname:             h.Hostname,
			RemoteAddr:           h.RemoteAddr,
			Status:               h.Status,
			ConnectedDurationSec: durationSec,
			LastHeartbeatNs:      h.LastHeartbeat,
			Stats: &management.HunterStats{
				PacketsCaptured:  h.PacketsCaptured,
				PacketsForwarded: h.PacketsForwarded,
				ActiveFilters:    h.ActiveFilters,
			},
			Interfaces:   h.Interfaces,
			Capabilities: h.Capabilities,
		})
	}

	// Inject virtual hunter for TAP nodes (local capture)
	if virtualHunter := p.SynthesizeVirtualHunter(); virtualHunter != nil {
		// Prepend virtual hunter so it appears first
		connectedHunters = append([]*management.ConnectedHunter{virtualHunter}, connectedHunters...)
	}

	// Get processor stats
	processorStats := p.statsCollector.GetProto()

	// Get upstream processor ID (empty if this is the root processor)
	upstreamProcessorID := ""
	if p.upstreamManager != nil {
		upstreamProcessorID = p.upstreamManager.GetUpstreamProcessorID()
	}

	// Determine node type and capture interfaces
	nodeType := management.NodeType_NODE_TYPE_PROCESSOR
	var captureInterfaces []string
	if p.IsLocalMode() {
		nodeType = management.NodeType_NODE_TYPE_TAP
		captureInterfaces = p.GetCaptureInterfaces()
	}

	// Recursively query downstream processors
	node, err := p.downstreamManager.GetTopology(
		ctx,
		p.config.ProcessorID,
		processorStats.Status,
		upstreamProcessorID,
		connectedHunters,
		nodeType,
		captureInterfaces,
	)
	if err != nil {
		return nil, err
	}

	return &management.TopologyResponse{
		Processor: node,
	}, nil
}

// SubscribeTopology subscribes to real-time topology updates (Management Service)
// Clients should call GetTopology() first to get the current state, then subscribe for updates
func (p *Processor) SubscribeTopology(req *management.TopologySubscribeRequest, stream management.ManagementService_SubscribeTopologyServer) error {
	// Generate subscriber ID from request
	subscriberID := req.ClientId
	if subscriberID == "" {
		subscriberID = fmt.Sprintf("subscriber-%d", time.Now().UnixNano())
	}

	logger.Info("Topology subscription request",
		"subscriber_id", subscriberID,
		"include_downstream", req.IncludeDownstream)

	// Register subscriber in proxy manager
	updateChan := p.proxyManager.RegisterSubscriber(subscriberID)

	// Cleanup on disconnect
	defer func() {
		p.proxyManager.UnregisterSubscriber(subscriberID)
		logger.Info("Topology subscription ended", "subscriber_id", subscriberID)
	}()

	logger.Info("Topology subscription active, streaming updates", "subscriber_id", subscriberID)

	// Stream topology updates
	for {
		select {
		case <-stream.Context().Done():
			logger.Debug("SubscribeTopology: stream context cancelled",
				"subscriber_id", subscriberID,
				"error", stream.Context().Err())
			return nil
		case update, ok := <-updateChan:
			if !ok {
				logger.Debug("SubscribeTopology: update channel closed",
					"subscriber_id", subscriberID)
				return nil
			}

			logger.Debug("Sending topology update",
				"subscriber_id", subscriberID,
				"update_type", update.UpdateType)

			if err := stream.Send(update); err != nil {
				logger.Error("Failed to send topology update",
					"subscriber_id", subscriberID,
					"error", err)
				return err
			}

			logger.Debug("Topology update sent successfully",
				"subscriber_id", subscriberID,
				"update_type", update.UpdateType)
		}
	}
}

// UpdateFilter adds or modifies a filter (Management Service)
func (p *Processor) UpdateFilter(ctx context.Context, filter *management.Filter) (*management.FilterUpdateResult, error) {
	logger.Info("Update filter request", "filter_id", filter.Id, "type", filter.Type, "pattern", filter.Pattern)

	// Store filter and distribute to hunters (distributed mode)
	huntersUpdated, err := p.filterManager.Update(filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update filter: %v", err)
	}

	// For tap mode (LocalTarget), also apply the filter locally to restart capture
	// with updated BPF filter and application-layer filters
	if localTarget, ok := p.filterTarget.(*filtering.LocalTarget); ok {
		if _, err := localTarget.ApplyFilter(filter); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to apply filter locally: %v", err)
		}
	}

	logger.Info("Filter updated",
		"filter_id", filter.Id,
		"hunters_updated", huntersUpdated)

	return &management.FilterUpdateResult{
		Success:        true,
		HuntersUpdated: huntersUpdated,
	}, nil
}

// DeleteFilter removes a filter (Management Service)
func (p *Processor) DeleteFilter(ctx context.Context, req *management.FilterDeleteRequest) (*management.FilterUpdateResult, error) {
	logger.Info("Delete filter request", "filter_id", req.FilterId)

	// Remove filter and notify hunters (distributed mode)
	huntersUpdated, err := p.filterManager.Delete(req.FilterId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "filter not found: %s", req.FilterId)
	}

	// For tap mode (LocalTarget), also remove the filter locally to restart capture
	// with updated BPF filter and application-layer filters
	if localTarget, ok := p.filterTarget.(*filtering.LocalTarget); ok {
		if _, err := localTarget.RemoveFilter(req.FilterId); err != nil {
			logger.Warn("Failed to remove filter locally", "filter_id", req.FilterId, "error", err)
		}
	}

	logger.Info("Filter deleted",
		"filter_id", req.FilterId,
		"hunters_updated", huntersUpdated)

	return &management.FilterUpdateResult{
		Success:        true,
		HuntersUpdated: huntersUpdated,
	}, nil
}

// UpdateFilterOnProcessor adds or modifies a filter on a specific processor (Management Service)
// Implements processor-scoped filter operations for multi-level management
func (p *Processor) UpdateFilterOnProcessor(ctx context.Context, req *management.ProcessorFilterRequest) (*management.FilterUpdateResult, error) {
	// Extract audit context for logging
	audit := extractAuditContext(ctx, "UpdateFilter")

	// Log operation start with filter details
	logAuditOperationStart(audit, req.ProcessorId,
		"filter_id", req.Filter.Id,
		"filter_type", req.Filter.Type,
		"filter_pattern", req.Filter.Pattern)

	// Verify authorization token if present (must happen before routing)
	if req.AuthToken != nil {
		// Convert protobuf token to internal type
		token, err := proxy.ConvertProtoToken(req.AuthToken)
		if err != nil {
			logAuditAuthFailure(audit, req.ProcessorId, "token_conversion_failed: "+err.Error(), 0)
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"reason", "invalid_auth_token")
			return nil, status.Errorf(codes.Unauthenticated, "invalid authorization token: %v", err)
		}

		// Verify token signature and expiration
		if err := p.proxyManager.VerifyAuthToken(token, req.ProcessorId); err != nil {
			logAuditAuthFailure(audit, req.ProcessorId, err.Error(), 0)
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"reason", "auth_verification_failed",
				"issuer_id", req.AuthToken.IssuerId,
				"expires_at", token.ExpiresAt)
			return nil, status.Errorf(codes.Unauthenticated, "authorization failed: %v", err)
		}

		logAuditAuthSuccess(audit, req.ProcessorId, req.AuthToken.IssuerId, 0)
	}

	// Use proxy manager to determine routing
	routingDecision, err := p.proxyManager.RouteToProcessor(ctx, req.ProcessorId)
	if err != nil {
		// RouteToProcessor returns gRPC status errors
		logAuditOperationResult(audit, req.ProcessorId, false, err, "reason", "routing_failed")
		return nil, err
	}

	// Check if target is local processor
	if routingDecision.IsLocal {
		// Handle locally
		logger.Debug("Target is local processor, handling directly")

		huntersUpdated, err := p.filterManager.Update(req.Filter)
		if err != nil {
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"filter_id", req.Filter.Id,
				"chain_depth", 0)
			return nil, status.Errorf(codes.Internal, "failed to update filter: %v", err)
		}

		logAuditOperationResult(audit, req.ProcessorId, true, nil,
			"filter_id", req.Filter.Id,
			"hunters_updated", huntersUpdated,
			"chain_depth", 0)

		return &management.FilterUpdateResult{
			Success:        true,
			HuntersUpdated: huntersUpdated,
		}, nil
	}

	// Target is a downstream processor - need to route the request
	logger.Debug("Target is downstream processor, routing request",
		"target_processor_id", req.ProcessorId,
		"downstream_processor_id", routingDecision.DownstreamProcessorID,
		"chain_depth", routingDecision.Depth,
		"recommended_timeout", routingDecision.RecommendedTimeout)

	// Build processor path for chain error context
	processorPath := []string{p.config.ProcessorID}

	// Apply recommended timeout to context for this operation
	// Timeout scales with chain depth: 5s base + 500ms per hop
	timeoutCtx, cancel := context.WithTimeout(ctx, routingDecision.RecommendedTimeout)
	defer cancel()

	// Forward request using downstream manager (handles chain error wrapping)
	result, err := p.downstreamManager.ForwardUpdateFilter(
		timeoutCtx,
		routingDecision.DownstreamProcessorID,
		req,
		processorPath,
		p.config.ProcessorID,
	)
	if err != nil {
		logAuditOperationResult(audit, req.ProcessorId, false, err,
			"reason", "forward_failed",
			"downstream_processor_id", routingDecision.DownstreamProcessorID,
			"chain_depth", routingDecision.Depth)
		// Convert ChainError to gRPC status if needed
		return nil, p.convertChainErrorToStatus(err)
	}

	logAuditOperationResult(audit, req.ProcessorId, true, nil,
		"filter_id", req.Filter.Id,
		"hunters_updated", result.HuntersUpdated,
		"chain_depth", routingDecision.Depth)

	return result, nil
}

// DeleteFilterOnProcessor removes a filter from a specific processor (Management Service)
// Implements processor-scoped filter operations for multi-level management
func (p *Processor) DeleteFilterOnProcessor(ctx context.Context, req *management.ProcessorFilterDeleteRequest) (*management.FilterUpdateResult, error) {
	// Extract audit context for logging
	audit := extractAuditContext(ctx, "DeleteFilter")

	// Log operation start
	logAuditOperationStart(audit, req.ProcessorId,
		"filter_id", req.FilterId)

	// Verify authorization token if present (must happen before routing)
	if req.AuthToken != nil {
		// Convert protobuf token to internal type
		token, err := proxy.ConvertProtoToken(req.AuthToken)
		if err != nil {
			logAuditAuthFailure(audit, req.ProcessorId, "token_conversion_failed: "+err.Error(), 0)
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"reason", "invalid_auth_token")
			return nil, status.Errorf(codes.Unauthenticated, "invalid authorization token: %v", err)
		}

		// Verify token signature and expiration
		if err := p.proxyManager.VerifyAuthToken(token, req.ProcessorId); err != nil {
			logAuditAuthFailure(audit, req.ProcessorId, err.Error(), 0)
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"reason", "auth_verification_failed",
				"issuer_id", req.AuthToken.IssuerId,
				"expires_at", token.ExpiresAt)
			return nil, status.Errorf(codes.Unauthenticated, "authorization failed: %v", err)
		}

		logAuditAuthSuccess(audit, req.ProcessorId, req.AuthToken.IssuerId, 0)
	}

	// Use proxy manager to determine routing
	routingDecision, err := p.proxyManager.RouteToProcessor(ctx, req.ProcessorId)
	if err != nil {
		// RouteToProcessor returns gRPC status errors
		logAuditOperationResult(audit, req.ProcessorId, false, err, "reason", "routing_failed")
		return nil, err
	}

	// Check if target is local processor
	if routingDecision.IsLocal {
		// Handle locally
		logger.Debug("Target is local processor, handling directly")

		huntersUpdated, err := p.filterManager.Delete(req.FilterId)
		if err != nil {
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"filter_id", req.FilterId,
				"chain_depth", 0)
			return nil, status.Errorf(codes.Internal, "failed to delete filter: %v", err)
		}

		logAuditOperationResult(audit, req.ProcessorId, true, nil,
			"filter_id", req.FilterId,
			"hunters_updated", huntersUpdated,
			"chain_depth", 0)

		return &management.FilterUpdateResult{
			Success:        true,
			HuntersUpdated: huntersUpdated,
		}, nil
	}

	// Target is a downstream processor - need to route the request
	logger.Debug("Target is downstream processor, routing request",
		"target_processor_id", req.ProcessorId,
		"downstream_processor_id", routingDecision.DownstreamProcessorID,
		"chain_depth", routingDecision.Depth,
		"recommended_timeout", routingDecision.RecommendedTimeout)

	// Build processor path for chain error context
	processorPath := []string{p.config.ProcessorID}

	// Apply recommended timeout to context for this operation
	// Timeout scales with chain depth: 5s base + 500ms per hop
	timeoutCtx, cancel := context.WithTimeout(ctx, routingDecision.RecommendedTimeout)
	defer cancel()

	// Forward request using downstream manager (handles chain error wrapping)
	result, err := p.downstreamManager.ForwardDeleteFilter(
		timeoutCtx,
		routingDecision.DownstreamProcessorID,
		req,
		processorPath,
		p.config.ProcessorID,
	)
	if err != nil {
		logAuditOperationResult(audit, req.ProcessorId, false, err,
			"reason", "forward_failed",
			"downstream_processor_id", routingDecision.DownstreamProcessorID,
			"chain_depth", routingDecision.Depth)
		// Convert ChainError to gRPC status if needed
		return nil, p.convertChainErrorToStatus(err)
	}

	logAuditOperationResult(audit, req.ProcessorId, true, nil,
		"filter_id", req.FilterId,
		"hunters_updated", result.HuntersUpdated,
		"chain_depth", routingDecision.Depth)

	return result, nil
}

// GetFiltersFromProcessor retrieves filters from a specific processor (Management Service)
// Implements processor-scoped filter queries for multi-level management
func (p *Processor) GetFiltersFromProcessor(ctx context.Context, req *management.ProcessorFilterQuery) (*management.FilterResponse, error) {
	// Extract audit context for logging
	audit := extractAuditContext(ctx, "GetFilters")

	// Log operation start
	logAuditOperationStart(audit, req.ProcessorId,
		"hunter_id", req.HunterId)

	// Use proxy manager to determine routing
	routingDecision, err := p.proxyManager.RouteToProcessor(ctx, req.ProcessorId)
	if err != nil {
		// RouteToProcessor returns gRPC status errors
		logAuditOperationResult(audit, req.ProcessorId, false, err, "reason", "routing_failed")
		return nil, err
	}

	// Check if target is local processor
	if routingDecision.IsLocal {
		// Handle locally
		logger.Debug("Target is local processor, handling directly")

		var filters []*management.Filter
		if req.HunterId == "" {
			// Return all filters for TUI/administrative queries
			filters = p.filterManager.GetAll()
		} else {
			// Return filters filtered by hunter capabilities and targeting
			filters = p.filterManager.GetForHunter(req.HunterId)
		}

		logAuditOperationResult(audit, req.ProcessorId, true, nil,
			"hunter_id", req.HunterId,
			"filter_count", len(filters),
			"chain_depth", 0)

		return &management.FilterResponse{
			Filters: filters,
		}, nil
	}

	// Target is a downstream processor - need to route the request
	logger.Debug("Target is downstream processor, routing request",
		"target_processor_id", req.ProcessorId,
		"downstream_processor_id", routingDecision.DownstreamProcessorID,
		"chain_depth", routingDecision.Depth,
		"recommended_timeout", routingDecision.RecommendedTimeout)

	// Verify authorization token if present
	if req.AuthToken != nil {
		// Convert protobuf token to internal type
		token, err := proxy.ConvertProtoToken(req.AuthToken)
		if err != nil {
			logAuditAuthFailure(audit, req.ProcessorId, "token_conversion_failed: "+err.Error(), routingDecision.Depth)
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"reason", "invalid_auth_token",
				"chain_depth", routingDecision.Depth)
			return nil, status.Errorf(codes.Unauthenticated, "invalid authorization token: %v", err)
		}

		// Verify token signature and expiration
		if err := p.proxyManager.VerifyAuthToken(token, req.ProcessorId); err != nil {
			logAuditAuthFailure(audit, req.ProcessorId, err.Error(), routingDecision.Depth)
			logAuditOperationResult(audit, req.ProcessorId, false, err,
				"reason", "auth_verification_failed",
				"issuer_id", req.AuthToken.IssuerId,
				"expires_at", token.ExpiresAt,
				"chain_depth", routingDecision.Depth)
			return nil, status.Errorf(codes.Unauthenticated, "authorization failed: %v", err)
		}

		logAuditAuthSuccess(audit, req.ProcessorId, req.AuthToken.IssuerId, routingDecision.Depth)
	}

	// Build processor path for chain error context
	processorPath := []string{p.config.ProcessorID}

	// Apply recommended timeout to context for this operation
	// Timeout scales with chain depth: 5s base + 500ms per hop
	timeoutCtx, cancel := context.WithTimeout(ctx, routingDecision.RecommendedTimeout)
	defer cancel()

	// Forward request using downstream manager (handles chain error wrapping)
	result, err := p.downstreamManager.ForwardGetFilters(
		timeoutCtx,
		routingDecision.DownstreamProcessorID,
		req,
		processorPath,
		p.config.ProcessorID,
	)
	if err != nil {
		logAuditOperationResult(audit, req.ProcessorId, false, err,
			"reason", "forward_failed",
			"downstream_processor_id", routingDecision.DownstreamProcessorID,
			"chain_depth", routingDecision.Depth)
		// Convert ChainError to gRPC status if needed
		return nil, p.convertChainErrorToStatus(err)
	}

	logAuditOperationResult(audit, req.ProcessorId, true, nil,
		"hunter_id", req.HunterId,
		"filter_count", len(result.Filters),
		"chain_depth", routingDecision.Depth)

	return result, nil
}

// RequestAuthToken issues an authorization token for proxied operations.
// The token is signed by this processor and can be verified by downstream processors.
// Tokens are valid for 5 minutes and authorize operations on the specified target processor.
func (p *Processor) RequestAuthToken(ctx context.Context, req *management.AuthTokenRequest) (*management.AuthorizationToken, error) {
	// Extract audit context for logging
	audit := extractAuditContext(ctx, "RequestAuthToken")

	// Log operation start
	logAuditOperationStart(audit, req.TargetProcessorId)

	// Issue token via proxy manager
	token, err := p.proxyManager.IssueAuthToken(req.TargetProcessorId)
	if err != nil {
		logger.Error("Failed to issue authorization token",
			"error", err,
			"target_processor_id", req.TargetProcessorId,
			"requester_addr", audit.RemoteAddr,
			"requester_cn", audit.CommonName)
		logAuditOperationResult(audit, req.TargetProcessorId, false, err,
			"reason", "token_issuance_failed")
		return nil, status.Errorf(codes.Internal, "failed to issue authorization token: %v", err)
	}

	// Log successful token issuance
	logger.Info("Issued authorization token",
		"target_processor_id", req.TargetProcessorId,
		"requester_addr", audit.RemoteAddr,
		"requester_cn", audit.CommonName,
		"expires_at", token.ExpiresAt)

	logAuditOperationResult(audit, req.TargetProcessorId, true, nil,
		"expires_at", token.ExpiresAt.Unix())

	// Convert internal token to protobuf format
	// TODO: Get processor chain from topology cache for auditing
	protoToken := proxy.ConvertToProtoToken(token, p.config.ProcessorID, []string{})

	return protoToken, nil
}

// SubscribePackets allows TUI/monitoring clients to subscribe to packet streams.
//
// SECURITY NOTE: Subscriber authentication relies on the gRPC server's TLS configuration.
//   - When TLSClientAuth=true (mutual TLS): Subscribers must present valid client certificates.
//     This provides strong authentication and is REQUIRED for production deployments.
//   - When TLSClientAuth=false: Any network client can subscribe and view packet data.
//     This is INSECURE and should only be used in trusted development environments.
//   - When TLSEnabled=false: All traffic is unencrypted and unauthenticated (CRITICAL risk).
//
// For production deployments, set LIPPYCAT_PRODUCTION=true to enforce mutual TLS.
func (p *Processor) SubscribePackets(req *data.SubscribeRequest, stream data.DataService_SubscribePacketsServer) error {
	clientID := req.ClientId
	if clientID == "" {
		nextID := p.subscriberManager.NextID()
		clientID = fmt.Sprintf("subscriber-%d", nextID)
	}

	// Check subscriber limit to prevent DoS
	if p.subscriberManager.CheckLimit() {
		count := p.subscriberManager.Count()
		logger.Warn("Subscriber limit reached, rejecting new subscriber",
			"client_id", clientID,
			"current_subscribers", count,
			"max_subscribers", p.config.MaxSubscribers)
		return status.Errorf(codes.ResourceExhausted,
			"maximum number of subscribers (%d) reached", p.config.MaxSubscribers)
	}

	// Compile BPF filter if specified
	var bpfFilter *BPFFilter
	if req.BpfFilter != "" {
		var err error
		bpfFilter, err = NewBPFFilter(req.BpfFilter)
		if err != nil {
			logger.Warn("Invalid BPF filter expression",
				"client_id", clientID,
				"filter", req.BpfFilter,
				"error", err)
			return status.Errorf(codes.InvalidArgument, "invalid BPF filter: %v", err)
		}
		logger.Info("BPF filter compiled for subscriber",
			"client_id", clientID,
			"filter", req.BpfFilter)
	}

	// Store hunter subscription filter for this client
	// has_hunter_filter = false: subscribe to all hunters (default/backward compatibility)
	// has_hunter_filter = true + empty list: subscribe to no hunters (explicit opt-out)
	// has_hunter_filter = true + non-empty list: subscribe to specified hunters only
	if req.HasHunterFilter {
		p.subscriberManager.SetFilter(clientID, req.HunterIds)
		if len(req.HunterIds) > 0 {
			logger.Info("New packet subscriber with hunter filter",
				"client_id", clientID,
				"subscribed_hunters", req.HunterIds)
		} else {
			logger.Info("New packet subscriber (no hunters - empty filter)",
				"client_id", clientID)
		}
	} else {
		logger.Info("New packet subscriber (all hunters - no filter)", "client_id", clientID)
	}

	// Create channel for this subscriber
	subChan := p.subscriberManager.Add(clientID)

	// Cleanup on disconnect
	defer func() {
		p.subscriberManager.Remove(clientID)
		logger.Info("Packet subscriber disconnected", "client_id", clientID)
	}()

	// Stream packets to client
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case batch, ok := <-subChan:
			if !ok {
				return nil
			}

			// Apply BPF filter if specified
			if bpfFilter != nil {
				batch = bpfFilter.FilterBatch(batch)
				if batch == nil {
					// All packets filtered out, skip this batch
					continue
				}
			}

			// Filter by hunter IDs if filter is explicitly set
			// has_hunter_filter = false: send all packets (no filter)
			// has_hunter_filter = true + empty list: send no packets (explicit opt-out)
			// has_hunter_filter = true + non-empty list: send only matching packets
			if req.HasHunterFilter {
				if len(req.HunterIds) == 0 {
					// Empty filter = subscribe to no hunters, don't send this packet
					continue
				}

				// Non-empty filter = check if this hunter matches
				found := false
				for _, hunterID := range req.HunterIds {
					if batch.HunterId == hunterID {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			if err := stream.Send(batch); err != nil {
				logger.Error("Failed to send batch to subscriber", "error", err, "client_id", clientID)
				return err
			}
		}
	}
}

// SubscribeCorrelatedCalls streams correlated call updates to monitoring clients (Data Service)
func (p *Processor) SubscribeCorrelatedCalls(req *data.SubscribeRequest, stream data.DataService_SubscribeCorrelatedCallsServer) error {
	clientID := req.ClientId
	if clientID == "" {
		clientID = fmt.Sprintf("correlation-subscriber-%d", time.Now().UnixNano())
	}

	logger.Info("New correlated calls subscriber", "client_id", clientID)

	// Create a ticker to send periodic updates
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Send initial snapshot of all correlated calls
	calls := p.callCorrelator.GetCorrelatedCalls()
	for _, call := range calls {
		update := correlatedCallToProto(call)
		if err := stream.Send(update); err != nil {
			logger.Error("Failed to send initial correlated call", "client_id", clientID, "error", err)
			return err
		}
	}

	logger.Info("Sent initial correlated calls", "client_id", clientID, "count", len(calls))

	// Stream periodic updates
	for {
		select {
		case <-stream.Context().Done():
			logger.Debug("SubscribeCorrelatedCalls: stream context cancelled", "client_id", clientID)
			return nil
		case <-ticker.C:
			// Send updated state for all active calls
			calls := p.callCorrelator.GetCorrelatedCalls()
			for _, call := range calls {
				update := correlatedCallToProto(call)
				if err := stream.Send(update); err != nil {
					logger.Error("Failed to send correlated call update", "client_id", clientID, "error", err)
					return err
				}
			}
		}
	}
}

// Helper functions

// buildTLSCredentials creates TLS credentials for gRPC server
func (p *Processor) buildTLSCredentials() (credentials.TransportCredentials, error) {
	return tlsutil.BuildServerCredentials(tlsutil.ServerConfig{
		CertFile:   p.config.TLSCertFile,
		KeyFile:    p.config.TLSKeyFile,
		CAFile:     p.config.TLSCAFile,
		ClientAuth: p.config.TLSClientAuth,
	})
}

// convertChainErrorToStatus converts a ChainError to a gRPC status error.
// If the error is not a ChainError, it returns the error wrapped in a standard status.
//
// This helper ensures that chain errors are properly converted with full context
// preserved in the gRPC error message.
func (p *Processor) convertChainErrorToStatus(err error) error {
	if err == nil {
		return nil
	}

	// Check if error is a ChainError
	if chainErr, ok := proxy.IsChainError(err); ok {
		// Convert using ChainError's GRPCStatus method
		return chainErr.GRPCStatus().Err()
	}

	// Not a ChainError, wrap in standard gRPC status
	// Try to preserve existing gRPC status code if present
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}

	// Default to Internal error
	return status.Errorf(codes.Internal, "%v", err)
}

// correlatedCallToProto converts a CorrelatedCall to protobuf CorrelatedCallUpdate
func correlatedCallToProto(call *CorrelatedCall) *data.CorrelatedCallUpdate {
	// Convert call legs to protobuf
	legs := make([]*data.CallLegInfo, 0, len(call.CallLegs))
	for _, leg := range call.CallLegs {
		legInfo := &data.CallLegInfo{
			CallId:       leg.CallID,
			HunterId:     leg.HunterID,
			SrcIp:        leg.SrcIP,
			DstIp:        leg.DstIP,
			Method:       leg.Method,
			ResponseCode: leg.ResponseCode,
			PacketCount:  int32(leg.PacketCount),
			StartTimeNs:  leg.StartTime.UnixNano(),
			LastSeenNs:   leg.LastSeen.UnixNano(),
		}
		legs = append(legs, legInfo)
	}

	return &data.CorrelatedCallUpdate{
		CorrelationId: call.CorrelationID,
		TagPair:       call.TagPair[:],
		FromUser:      call.FromUser,
		ToUser:        call.ToUser,
		Legs:          legs,
		StartTimeNs:   call.StartTime.UnixNano(),
		LastSeenNs:    call.LastSeen.UnixNano(),
		State:         call.State.String(),
	}
}

// Audit logging helper functions

// auditContext extracts requester information from gRPC context for audit logging
type auditContext struct {
	RemoteAddr string
	CommonName string
	Operation  string
}

// extractAuditContext extracts audit information from gRPC context
func extractAuditContext(ctx context.Context, operation string) auditContext {
	audit := auditContext{
		Operation:  operation,
		RemoteAddr: "unknown",
		CommonName: "unknown",
	}

	// Extract peer information (remote address)
	if p, ok := peer.FromContext(ctx); ok {
		audit.RemoteAddr = p.Addr.String()

		// Extract TLS certificate info if present
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				cert := tlsInfo.State.PeerCertificates[0]
				audit.CommonName = cert.Subject.CommonName
			}
		}
	}

	return audit
}

// logAuditOperationStart logs the start of an audited operation
func logAuditOperationStart(audit auditContext, targetProcessorID string, additionalFields ...any) {
	fields := []any{
		"audit", "operation_start",
		"operation", audit.Operation,
		"requester_addr", audit.RemoteAddr,
		"requester_cn", audit.CommonName,
		"target_processor_id", targetProcessorID,
	}
	fields = append(fields, additionalFields...)
	logger.Info("AUDIT: Operation started", fields...)
}

// logAuditAuthSuccess logs successful authorization
func logAuditAuthSuccess(audit auditContext, targetProcessorID, issuerID string, chainDepth int32) {
	logger.Info("AUDIT: Authorization successful",
		"audit", "auth_success",
		"operation", audit.Operation,
		"requester_addr", audit.RemoteAddr,
		"requester_cn", audit.CommonName,
		"target_processor_id", targetProcessorID,
		"issuer_id", issuerID,
		"chain_depth", chainDepth)
}

// logAuditAuthFailure logs failed authorization
func logAuditAuthFailure(audit auditContext, targetProcessorID string, reason string, chainDepth int32) {
	logger.Warn("AUDIT: Authorization failed",
		"audit", "auth_failure",
		"operation", audit.Operation,
		"requester_addr", audit.RemoteAddr,
		"requester_cn", audit.CommonName,
		"target_processor_id", targetProcessorID,
		"reason", reason,
		"chain_depth", chainDepth)
}

// logAuditOperationResult logs the result of an audited operation
func logAuditOperationResult(audit auditContext, targetProcessorID string, success bool, err error, additionalFields ...any) {
	fields := []any{
		"audit", "operation_result",
		"operation", audit.Operation,
		"requester_addr", audit.RemoteAddr,
		"requester_cn", audit.CommonName,
		"target_processor_id", targetProcessorID,
		"success", success,
	}
	if err != nil {
		fields = append(fields, "error", err.Error())
	}
	fields = append(fields, additionalFields...)

	if success {
		logger.Info("AUDIT: Operation completed successfully", fields...)
	} else {
		logger.Warn("AUDIT: Operation failed", fields...)
	}
}

package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// TestRegisterHunter tests the RegisterHunter gRPC handler
func TestRegisterHunter(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		req          *management.HunterRegistration
		wantAccepted bool
		wantErr      bool
		errContains  string
		setupFilters bool // Whether to add filters before registration
		validateResp func(t *testing.T, resp *management.RegistrationResponse)
	}{
		{
			name: "successful registration",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
				MaxHunters:  10,
			},
			req: &management.HunterRegistration{
				HunterId:   "hunter-1",
				Hostname:   "host1",
				Interfaces: []string{"eth0"},
				Version:    "v1.0.0",
				Capabilities: &management.HunterCapabilities{
					FilterTypes:     []string{"sip_user", "ip_address"},
					MaxBufferSize:   1024000,
					GpuAcceleration: false,
					AfXdp:           false,
				},
			},
			wantAccepted: true,
			wantErr:      false,
			validateResp: func(t *testing.T, resp *management.RegistrationResponse) {
				assert.True(t, resp.Accepted)
				assert.Empty(t, resp.Error)
				assert.Equal(t, "hunter-1", resp.AssignedId)
				assert.NotNil(t, resp.Config)
				assert.Equal(t, "test-processor", resp.Config.ProcessorId)
				assert.Equal(t, uint32(64), resp.Config.BatchSize)
				assert.Greater(t, resp.Config.BatchTimeoutMs, uint32(0))
			},
		},
		{
			name: "successful registration with GPU capabilities",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
				MaxHunters:  10,
			},
			req: &management.HunterRegistration{
				HunterId:   "hunter-gpu",
				Hostname:   "host-gpu",
				Interfaces: []string{"eth0", "eth1"},
				Version:    "v1.0.0",
				Capabilities: &management.HunterCapabilities{
					FilterTypes:     []string{"sip_user", "ip_address", "bpf"},
					MaxBufferSize:   10240000,
					GpuAcceleration: true,
					AfXdp:           true,
				},
			},
			wantAccepted: true,
			wantErr:      false,
			validateResp: func(t *testing.T, resp *management.RegistrationResponse) {
				assert.True(t, resp.Accepted)
				assert.Equal(t, "hunter-gpu", resp.AssignedId)
			},
		},
		{
			name: "hunter re-registration (reconnect)",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
				MaxHunters:  10,
			},
			req: &management.HunterRegistration{
				HunterId:   "hunter-reconnect",
				Hostname:   "host1",
				Interfaces: []string{"eth0"},
				Version:    "v1.0.0",
			},
			wantAccepted: true,
			wantErr:      false,
			validateResp: func(t *testing.T, resp *management.RegistrationResponse) {
				assert.True(t, resp.Accepted)
				assert.Equal(t, "hunter-reconnect", resp.AssignedId)
			},
		},
		{
			name: "registration with filters",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
				MaxHunters:  10,
			},
			req: &management.HunterRegistration{
				HunterId:   "hunter-2",
				Hostname:   "host2",
				Interfaces: []string{"eth0"},
				Version:    "v1.0.0",
			},
			setupFilters: true,
			wantAccepted: true,
			wantErr:      false,
			validateResp: func(t *testing.T, resp *management.RegistrationResponse) {
				assert.True(t, resp.Accepted)
				assert.Equal(t, "hunter-2", resp.AssignedId)
				assert.NotNil(t, resp.Filters)
				// Filters will be added in the test setup
			},
		},
		{
			name: "empty hunter ID",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
				MaxHunters:  10,
			},
			req: &management.HunterRegistration{
				HunterId:   "",
				Hostname:   "host1",
				Interfaces: []string{"eth0"},
				Version:    "v1.0.0",
			},
			wantAccepted: true, // Currently the implementation doesn't validate empty hunter ID
			wantErr:      false,
		},
		{
			name: "minimal hunter registration",
			config: Config{
				ProcessorID: "test-processor",
				ListenAddr:  "localhost:50051",
				MaxHunters:  10,
			},
			req: &management.HunterRegistration{
				HunterId: "hunter-minimal",
			},
			wantAccepted: true,
			wantErr:      false,
			validateResp: func(t *testing.T, resp *management.RegistrationResponse) {
				assert.True(t, resp.Accepted)
				assert.Equal(t, "hunter-minimal", resp.AssignedId)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create processor
			processor, err := New(tt.config)
			require.NoError(t, err)
			require.NotNil(t, processor)

			// Setup filters if needed
			if tt.setupFilters {
				filter := &management.Filter{
					Id:            "filter-1",
					Type:          management.FilterType_FILTER_SIP_USER,
					Pattern:       "alice",
					TargetHunters: []string{}, // Empty = all hunters
					Enabled:       true,
					Description:   "Test filter",
				}
				_, err := processor.filterManager.Update(filter)
				require.NoError(t, err, "filter should be added successfully")
			}

			// For reconnect test, register the hunter first
			if tt.name == "hunter re-registration (reconnect)" {
				// First registration
				firstResp, err := processor.RegisterHunter(context.Background(), tt.req)
				require.NoError(t, err)
				require.True(t, firstResp.Accepted)
			}

			// Perform registration
			resp, err := processor.RegisterHunter(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			if tt.validateResp != nil {
				tt.validateResp(t, resp)
			}
		})
	}
}

// TestRegisterHunter_MaxHuntersLimit tests that registration fails when max hunters limit is reached
func TestRegisterHunter_MaxHuntersLimit(t *testing.T) {
	// Create processor with max 2 hunters
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  2,
	})
	require.NoError(t, err)
	require.NotNil(t, processor)

	// Register first hunter
	req1 := &management.HunterRegistration{
		HunterId:   "hunter-1",
		Hostname:   "host1",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
	}
	resp1, err := processor.RegisterHunter(context.Background(), req1)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	assert.True(t, resp1.Accepted)

	// Register second hunter
	req2 := &management.HunterRegistration{
		HunterId:   "hunter-2",
		Hostname:   "host2",
		Interfaces: []string{"eth1"},
		Version:    "v1.0.0",
	}
	resp2, err := processor.RegisterHunter(context.Background(), req2)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.True(t, resp2.Accepted)

	// Try to register third hunter - should fail
	req3 := &management.HunterRegistration{
		HunterId:   "hunter-3",
		Hostname:   "host3",
		Interfaces: []string{"eth2"},
		Version:    "v1.0.0",
	}
	_, err = processor.RegisterHunter(context.Background(), req3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ResourceExhausted")
	assert.Contains(t, err.Error(), "maximum number of hunters reached")
}

// TestRegisterHunter_ReconnectDoesNotCountAgainstLimit tests that reconnection doesn't count against max hunters
func TestRegisterHunter_ReconnectDoesNotCountAgainstLimit(t *testing.T) {
	// Create processor with max 1 hunter
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  1,
	})
	require.NoError(t, err)
	require.NotNil(t, processor)

	// Register hunter
	req := &management.HunterRegistration{
		HunterId:   "hunter-1",
		Hostname:   "host1",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
	}
	resp1, err := processor.RegisterHunter(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	assert.True(t, resp1.Accepted)

	// Re-register same hunter (simulating reconnection)
	resp2, err := processor.RegisterHunter(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.True(t, resp2.Accepted, "reconnection should succeed even at max capacity")

	// Try to register different hunter - should fail
	req2 := &management.HunterRegistration{
		HunterId:   "hunter-2",
		Hostname:   "host2",
		Interfaces: []string{"eth1"},
		Version:    "v1.0.0",
	}
	_, err = processor.RegisterHunter(context.Background(), req2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of hunters reached")
}

// TestRegisterHunter_FiltersInResponse tests that filters are included in registration response
func TestRegisterHunter_FiltersInResponse(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	require.NotNil(t, processor)

	// Add global IP filter (applies to all hunters, supported by hunters without capabilities)
	globalFilter := &management.Filter{
		Id:            "global-filter",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Pattern:       "10.0.0.0/8",
		TargetHunters: []string{}, // Empty = all hunters
		Enabled:       true,
		Description:   "Global IP filter",
	}
	_, err = processor.filterManager.Update(globalFilter)
	require.NoError(t, err)

	// Add hunter-specific IP filter
	hunterFilter := &management.Filter{
		Id:            "hunter-specific",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Pattern:       "192.168.1.0/24",
		TargetHunters: []string{"hunter-1"},
		Enabled:       true,
		Description:   "Hunter-specific filter",
	}
	_, err = processor.filterManager.Update(hunterFilter)
	require.NoError(t, err)

	// Add SIP filter that won't be returned to hunters without capabilities
	sipFilter := &management.Filter{
		Id:            "sip-filter",
		Type:          management.FilterType_FILTER_SIP_USER,
		Pattern:       "alice",
		TargetHunters: []string{},
		Enabled:       true,
		Description:   "SIP filter (only for VoIP hunters)",
	}
	_, err = processor.filterManager.Update(sipFilter)
	require.NoError(t, err)

	// Register hunter without capabilities (legacy hunter - only gets IP/BPF filters)
	req := &management.HunterRegistration{
		HunterId:   "hunter-1",
		Hostname:   "host1",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
		// No capabilities = legacy hunter
	}
	resp, err := processor.RegisterHunter(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Accepted)

	// Verify filters are in response (should get both IP filters, but not SIP)
	assert.NotNil(t, resp.Filters)
	assert.Len(t, resp.Filters, 2, "should receive both IP filters but not SIP")

	// Verify filter IDs
	filterIDs := make([]string, len(resp.Filters))
	for i, f := range resp.Filters {
		filterIDs[i] = f.Id
	}
	assert.Contains(t, filterIDs, "global-filter")
	assert.Contains(t, filterIDs, "hunter-specific")
	assert.NotContains(t, filterIDs, "sip-filter", "SIP filter should not be sent to legacy hunter")

	// Register VoIP hunter with SIP capabilities
	voipReq := &management.HunterRegistration{
		HunterId:   "hunter-voip",
		Hostname:   "host-voip",
		Interfaces: []string{"eth1"},
		Version:    "v1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes: []string{"sip_user", "ip_address"}, // Use lowercase format
		},
	}
	voipResp, err := processor.RegisterHunter(context.Background(), voipReq)
	require.NoError(t, err)
	require.NotNil(t, voipResp)
	assert.True(t, voipResp.Accepted)

	// VoIP hunter should get all global filters (IP + SIP)
	assert.NotNil(t, voipResp.Filters)
	assert.Len(t, voipResp.Filters, 2, "should receive global IP and SIP filters")

	voipFilterIDs := make([]string, len(voipResp.Filters))
	for i, f := range voipResp.Filters {
		voipFilterIDs[i] = f.Id
	}
	assert.Contains(t, voipFilterIDs, "global-filter")
	assert.Contains(t, voipFilterIDs, "sip-filter")

	// Register different legacy hunter - should only get global IP filter
	req2 := &management.HunterRegistration{
		HunterId:   "hunter-2",
		Hostname:   "host2",
		Interfaces: []string{"eth1"},
		Version:    "v1.0.0",
	}
	resp2, err := processor.RegisterHunter(context.Background(), req2)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.True(t, resp2.Accepted)

	assert.NotNil(t, resp2.Filters)
	assert.Len(t, resp2.Filters, 1, "should only receive global IP filter")
	assert.Equal(t, "global-filter", resp2.Filters[0].Id)
}

// TestRegisterHunter_ProcessorConfig tests that processor configuration is correctly returned
func TestRegisterHunter_ProcessorConfig(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "my-processor-id",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	require.NotNil(t, processor)

	req := &management.HunterRegistration{
		HunterId:   "hunter-1",
		Hostname:   "host1",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
	}
	resp, err := processor.RegisterHunter(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Accepted)

	// Verify processor config
	require.NotNil(t, resp.Config)
	assert.Equal(t, "my-processor-id", resp.Config.ProcessorId)
	assert.Equal(t, uint32(64), resp.Config.BatchSize)
	assert.Greater(t, resp.Config.BatchTimeoutMs, uint32(0))
	assert.Equal(t, uint32(5), resp.Config.ReconnectIntervalSec)
	assert.Equal(t, uint32(0), resp.Config.MaxReconnectAttempts) // 0 = infinite
}

// TestRegisterHunter_Concurrent tests concurrent hunter registrations
func TestRegisterHunter_Concurrent(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  100,
	})
	require.NoError(t, err)
	require.NotNil(t, processor)

	// Register 50 hunters concurrently
	const numHunters = 50
	results := make(chan error, numHunters)

	for i := 0; i < numHunters; i++ {
		go func(id int) {
			req := &management.HunterRegistration{
				HunterId:   fmt.Sprintf("hunter-%d", id),
				Hostname:   fmt.Sprintf("host-%d", id),
				Interfaces: []string{"eth0"},
				Version:    "v1.0.0",
			}
			resp, err := processor.RegisterHunter(context.Background(), req)
			if err != nil {
				results <- err
				return
			}
			if !resp.Accepted {
				results <- fmt.Errorf("registration rejected for hunter-%d", id)
				return
			}
			results <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numHunters; i++ {
		err := <-results
		require.NoError(t, err)
	}

	// Verify all hunters are registered
	statusResp, err := processor.GetHunterStatus(context.Background(), &management.StatusRequest{})
	require.NoError(t, err)
	assert.Len(t, statusResp.Hunters, numHunters)
}

// mockStreamPacketsServer is a mock implementation of DataService_StreamPacketsServer for testing
type mockStreamPacketsServer struct {
	data.DataService_StreamPacketsServer
	ctx             context.Context
	recvBatches     []*data.PacketBatch
	recvIndex       int
	sentControls    []*data.StreamControl
	mu              sync.Mutex
	recvErr         error // Error to return from Recv()
	sendErr         error // Error to return from Send()
	cancelAfterRecv int   // Cancel context after N Recv() calls (0 = don't cancel)
}

func (m *mockStreamPacketsServer) Context() context.Context {
	return m.ctx
}

func (m *mockStreamPacketsServer) Recv() (*data.PacketBatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we should cancel context
	if m.cancelAfterRecv > 0 && m.recvIndex >= m.cancelAfterRecv {
		return nil, context.Canceled
	}

	// Return configured error
	if m.recvErr != nil {
		return nil, m.recvErr
	}

	// Return EOF if no more batches
	if m.recvIndex >= len(m.recvBatches) {
		return nil, io.EOF
	}

	batch := m.recvBatches[m.recvIndex]
	m.recvIndex++
	return batch, nil
}

func (m *mockStreamPacketsServer) Send(ctrl *data.StreamControl) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return configured error
	if m.sendErr != nil {
		return m.sendErr
	}

	m.sentControls = append(m.sentControls, ctrl)
	return nil
}

func (m *mockStreamPacketsServer) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockStreamPacketsServer) RecvMsg(msg interface{}) error {
	return nil
}

func (m *mockStreamPacketsServer) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockStreamPacketsServer) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockStreamPacketsServer) SetTrailer(metadata.MD) {}

// TestStreamPackets_Success tests successful packet streaming from a hunter
func TestStreamPackets_Success(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create packet batches
	batches := []*data.PacketBatch{
		{
			HunterId:    "hunter-1",
			Sequence:    1,
			TimestampNs: time.Now().UnixNano(),
			Packets: []*data.CapturedPacket{
				{
					Data:           []byte{0x01, 0x02, 0x03},
					TimestampNs:    time.Now().UnixNano(),
					CaptureLength:  3,
					OriginalLength: 3,
					LinkType:       1, // Ethernet
				},
			},
		},
		{
			HunterId:    "hunter-1",
			Sequence:    2,
			TimestampNs: time.Now().UnixNano(),
			Packets: []*data.CapturedPacket{
				{
					Data:           []byte{0x04, 0x05, 0x06},
					TimestampNs:    time.Now().UnixNano(),
					CaptureLength:  3,
					OriginalLength: 3,
					LinkType:       1,
				},
			},
		},
	}

	// Create mock stream
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockStreamPacketsServer{
		ctx:         ctx,
		recvBatches: batches,
	}

	// Run StreamPackets in goroutine (it blocks until EOF)
	done := make(chan error, 1)
	go func() {
		done <- processor.StreamPackets(mockStream)
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		assert.Equal(t, io.EOF, err)
	case <-time.After(10 * time.Second):
		t.Fatal("StreamPackets timed out")
	}

	// Verify acknowledgments were sent
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	assert.Len(t, mockStream.sentControls, 2)
	assert.Equal(t, uint64(1), mockStream.sentControls[0].AckSequence)
	assert.Equal(t, uint64(2), mockStream.sentControls[1].AckSequence)
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, mockStream.sentControls[0].FlowControl)
}

// TestStreamPackets_MultipleConcurrentHunters tests multiple hunters streaming simultaneously
func TestStreamPackets_MultipleConcurrentHunters(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	numHunters := 5
	var wg sync.WaitGroup
	wg.Add(numHunters)

	for i := 0; i < numHunters; i++ {
		hunterID := fmt.Sprintf("hunter-%d", i+1)

		go func(hid string) {
			defer wg.Done()

			// Create packet batch
			batch := &data.PacketBatch{
				HunterId:    hid,
				Sequence:    1,
				TimestampNs: time.Now().UnixNano(),
				Packets: []*data.CapturedPacket{
					{
						Data:           []byte{0x01, 0x02, 0x03},
						TimestampNs:    time.Now().UnixNano(),
						CaptureLength:  3,
						OriginalLength: 3,
						LinkType:       1,
					},
				},
			}

			// Create mock stream
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			mockStream := &mockStreamPacketsServer{
				ctx:         ctx,
				recvBatches: []*data.PacketBatch{batch},
			}

			// Stream packets
			err := processor.StreamPackets(mockStream)
			assert.Equal(t, io.EOF, err)

			// Verify acknowledgment
			mockStream.mu.Lock()
			defer mockStream.mu.Unlock()
			assert.Len(t, mockStream.sentControls, 1)
			assert.Equal(t, uint64(1), mockStream.sentControls[0].AckSequence)
		}(hunterID)
	}

	// Wait for all hunters to complete
	wg.Wait()

	// Verify stats
	stats := processor.statsCollector.GetProto()
	assert.Greater(t, stats.TotalPacketsReceived, uint64(0))
}

// TestStreamPackets_DisconnectHandling tests hunter disconnect (context cancellation)
func TestStreamPackets_DisconnectHandling(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create batches but configure to cancel after 2 receives
	batches := []*data.PacketBatch{
		{
			HunterId:    "hunter-disconnect",
			Sequence:    1,
			TimestampNs: time.Now().UnixNano(),
			Packets:     []*data.CapturedPacket{{Data: []byte{0x01}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
		},
		{
			HunterId:    "hunter-disconnect",
			Sequence:    2,
			TimestampNs: time.Now().UnixNano(),
			Packets:     []*data.CapturedPacket{{Data: []byte{0x02}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
		},
		// Third batch should never be received due to cancellation
		{
			HunterId:    "hunter-disconnect",
			Sequence:    3,
			TimestampNs: time.Now().UnixNano(),
			Packets:     []*data.CapturedPacket{{Data: []byte{0x03}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockStreamPacketsServer{
		ctx:             ctx,
		recvBatches:     batches,
		cancelAfterRecv: 2, // Cancel after 2 receives
	}

	// Stream packets (should stop after context cancellation)
	err = processor.StreamPackets(mockStream)
	assert.Equal(t, context.Canceled, err)

	// Verify only 2 batches were processed
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	assert.Len(t, mockStream.sentControls, 2) // Only 2 acknowledgments sent
}

// TestStreamPackets_FlowControl tests flow control signals
func TestStreamPackets_FlowControl(t *testing.T) {
	// Create processor with PCAP writer to trigger flow control
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
		WriteFile:   "/tmp/test-flow-control.pcap",
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create batches
	batch := &data.PacketBatch{
		HunterId:    "hunter-flow",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				Data:           []byte{0x01, 0x02, 0x03},
				TimestampNs:    time.Now().UnixNano(),
				CaptureLength:  3,
				OriginalLength: 3,
				LinkType:       1,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockStreamPacketsServer{
		ctx:         ctx,
		recvBatches: []*data.PacketBatch{batch},
	}

	// Stream packets
	err = processor.StreamPackets(mockStream)
	assert.Equal(t, io.EOF, err)

	// Verify flow control signal was sent
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	assert.Len(t, mockStream.sentControls, 1)
	// Flow control should be CONTINUE (queue not full)
	assert.Equal(t, data.FlowControl_FLOW_CONTINUE, mockStream.sentControls[0].FlowControl)
}

// TestStreamPackets_SendError tests handling of Send() errors
func TestStreamPackets_SendError(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-send-error",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte{0x01}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockStreamPacketsServer{
		ctx:         ctx,
		recvBatches: []*data.PacketBatch{batch},
		sendErr:     errors.New("mock send error"),
	}

	// StreamPackets should continue despite Send() error (as per implementation)
	err = processor.StreamPackets(mockStream)
	// Should still get EOF from Recv(), not the send error
	assert.Equal(t, io.EOF, err)
}

// TestStreamPackets_EmptyBatch tests handling of empty batches
func TestStreamPackets_EmptyBatch(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create empty batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-empty",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{}, // Empty
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockStreamPacketsServer{
		ctx:         ctx,
		recvBatches: []*data.PacketBatch{batch},
	}

	// Stream packets
	err = processor.StreamPackets(mockStream)
	assert.Equal(t, io.EOF, err)

	// Verify acknowledgment was still sent
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	assert.Len(t, mockStream.sentControls, 1)
}

// mockSubscribePacketsServer is a mock implementation of DataService_SubscribePacketsServer for testing
type mockSubscribePacketsServer struct {
	data.DataService_SubscribePacketsServer
	ctx         context.Context
	sentBatches []*data.PacketBatch
	mu          sync.Mutex
	sendErr     error // Error to return from Send()
	sendDelay   time.Duration
	cancelAfter int // Cancel context after N Send() calls (0 = don't cancel)
	sendCount   int
}

func (m *mockSubscribePacketsServer) Context() context.Context {
	return m.ctx
}

func (m *mockSubscribePacketsServer) Send(batch *data.PacketBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we should cancel context
	if m.cancelAfter > 0 && m.sendCount >= m.cancelAfter {
		return context.Canceled
	}

	m.sendCount++

	// Return configured error
	if m.sendErr != nil {
		return m.sendErr
	}

	// Add delay if configured (for slow subscriber simulation)
	if m.sendDelay > 0 {
		m.mu.Unlock()
		time.Sleep(m.sendDelay)
		m.mu.Lock()
	}

	m.sentBatches = append(m.sentBatches, batch)
	return nil
}

func (m *mockSubscribePacketsServer) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockSubscribePacketsServer) RecvMsg(msg interface{}) error {
	return nil
}

func (m *mockSubscribePacketsServer) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockSubscribePacketsServer) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockSubscribePacketsServer) SetTrailer(metadata.MD) {}

// TestSubscribePackets_Success tests successful packet subscription
func TestSubscribePackets_Success(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create mock stream
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockSubscribePacketsServer{
		ctx: ctx,
	}

	// Create subscribe request
	req := &data.SubscribeRequest{
		ClientId: "test-client-1",
	}

	// Run SubscribePackets in goroutine (it blocks until disconnect)
	done := make(chan error, 1)
	go func() {
		done <- processor.SubscribePackets(req, mockStream)
	}()

	// Wait for subscriber to be registered
	time.Sleep(100 * time.Millisecond)

	// Verify subscriber was added
	assert.Equal(t, 1, processor.subscriberManager.Count())

	// Simulate packet batch arriving (directly send to subscriber channel)
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				Data:           []byte{0x01, 0x02, 0x03},
				TimestampNs:    time.Now().UnixNano(),
				CaptureLength:  3,
				OriginalLength: 3,
				LinkType:       1,
			},
		},
	}

	// Broadcast to all subscribers
	processor.subscriberManager.Broadcast(batch)

	// Wait for batch to be sent
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop subscription
	cancel()

	// Wait for completion
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("SubscribePackets timed out")
	}

	// Verify batch was sent
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	require.Len(t, mockStream.sentBatches, 1)
	assert.Equal(t, "hunter-1", mockStream.sentBatches[0].HunterId)
	assert.Equal(t, uint64(1), mockStream.sentBatches[0].Sequence)

	// Verify subscriber was removed
	assert.Equal(t, 0, processor.subscriberManager.Count())
}

// TestSubscribePackets_WithHunterFilter tests subscription with hunter ID filter
func TestSubscribePackets_WithHunterFilter(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create mock stream
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockSubscribePacketsServer{
		ctx: ctx,
	}

	// Create subscribe request with hunter filter (only subscribe to hunter-2)
	req := &data.SubscribeRequest{
		ClientId:        "test-client-filter",
		HunterIds:       []string{"hunter-2"},
		HasHunterFilter: true,
	}

	// Run SubscribePackets in goroutine
	done := make(chan error, 1)
	go func() {
		done <- processor.SubscribePackets(req, mockStream)
	}()

	// Wait for subscriber to be registered
	time.Sleep(100 * time.Millisecond)

	// Send batches from different hunters
	batch1 := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte{0x01}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
	}

	batch2 := &data.PacketBatch{
		HunterId:    "hunter-2",
		Sequence:    2,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte{0x02}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
	}

	batch3 := &data.PacketBatch{
		HunterId:    "hunter-3",
		Sequence:    3,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte{0x03}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
	}

	// Broadcast all batches
	processor.subscriberManager.Broadcast(batch1)
	processor.subscriberManager.Broadcast(batch2)
	processor.subscriberManager.Broadcast(batch3)

	// Wait for batches to be processed
	time.Sleep(200 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for completion
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("SubscribePackets timed out")
	}

	// Verify only hunter-2's batch was sent (hunter filter)
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	require.Len(t, mockStream.sentBatches, 1)
	assert.Equal(t, "hunter-2", mockStream.sentBatches[0].HunterId)
	assert.Equal(t, uint64(2), mockStream.sentBatches[0].Sequence)
}

// TestSubscribePackets_EmptyHunterFilter tests subscription with empty hunter filter (no packets)
func TestSubscribePackets_EmptyHunterFilter(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create mock stream
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockSubscribePacketsServer{
		ctx: ctx,
	}

	// Create subscribe request with empty hunter filter (subscribe to no hunters)
	req := &data.SubscribeRequest{
		ClientId:        "test-client-empty-filter",
		HunterIds:       []string{}, // Empty list
		HasHunterFilter: true,       // Explicitly set filter
	}

	// Run SubscribePackets in goroutine
	done := make(chan error, 1)
	go func() {
		done <- processor.SubscribePackets(req, mockStream)
	}()

	// Wait for subscriber to be registered
	time.Sleep(100 * time.Millisecond)

	// Send batch from any hunter
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte{0x01}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
	}

	// Broadcast batch
	processor.subscriberManager.Broadcast(batch)

	// Wait for potential processing
	time.Sleep(200 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for completion
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("SubscribePackets timed out")
	}

	// Verify no batches were sent (empty filter = subscribe to no hunters)
	mockStream.mu.Lock()
	defer mockStream.mu.Unlock()
	assert.Len(t, mockStream.sentBatches, 0)
}

// TestSubscribePackets_DisconnectHandling tests subscriber disconnect
func TestSubscribePackets_DisconnectHandling(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create mock stream with early cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	mockStream := &mockSubscribePacketsServer{
		ctx: ctx,
	}

	// Create subscribe request
	req := &data.SubscribeRequest{
		ClientId: "test-client-disconnect",
	}

	// Run SubscribePackets in goroutine
	done := make(chan error, 1)
	go func() {
		done <- processor.SubscribePackets(req, mockStream)
	}()

	// Wait for subscriber to be registered
	time.Sleep(100 * time.Millisecond)

	// Verify subscriber was added
	assert.Equal(t, 1, processor.subscriberManager.Count())

	// Cancel context immediately (simulating client disconnect)
	cancel()

	// Wait for completion
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("SubscribePackets timed out")
	}

	// Verify subscriber was removed
	assert.Equal(t, 0, processor.subscriberManager.Count())
}

// TestSubscribePackets_SendError tests handling of Send() errors (slow subscriber)
func TestSubscribePackets_SendError(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create mock stream that returns error on Send()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockSubscribePacketsServer{
		ctx:     ctx,
		sendErr: errors.New("mock send error"),
	}

	// Create subscribe request
	req := &data.SubscribeRequest{
		ClientId: "test-client-send-error",
	}

	// Run SubscribePackets in goroutine
	done := make(chan error, 1)
	go func() {
		done <- processor.SubscribePackets(req, mockStream)
	}()

	// Wait for subscriber to be registered
	time.Sleep(100 * time.Millisecond)

	// Send batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte{0x01}, TimestampNs: time.Now().UnixNano(), CaptureLength: 1, OriginalLength: 1, LinkType: 1}},
	}

	// Broadcast batch
	processor.subscriberManager.Broadcast(batch)

	// Wait for completion (should error quickly)
	select {
	case err := <-done:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mock send error")
	case <-time.After(10 * time.Second):
		t.Fatal("SubscribePackets timed out")
	}

	// Verify subscriber was removed
	assert.Equal(t, 0, processor.subscriberManager.Count())
}

// TestSubscribePackets_MaxSubscribersLimit tests subscriber limit enforcement
func TestSubscribePackets_MaxSubscribersLimit(t *testing.T) {
	// Create processor with max 2 subscribers
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 2,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Add first subscriber
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	mockStream1 := &mockSubscribePacketsServer{ctx: ctx1}
	req1 := &data.SubscribeRequest{ClientId: "subscriber-1"}

	done1 := make(chan error, 1)
	go func() {
		done1 <- processor.SubscribePackets(req1, mockStream1)
	}()
	time.Sleep(50 * time.Millisecond)

	// Add second subscriber
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	mockStream2 := &mockSubscribePacketsServer{ctx: ctx2}
	req2 := &data.SubscribeRequest{ClientId: "subscriber-2"}

	done2 := make(chan error, 1)
	go func() {
		done2 <- processor.SubscribePackets(req2, mockStream2)
	}()
	time.Sleep(50 * time.Millisecond)

	// Verify we have 2 subscribers
	assert.Equal(t, 2, processor.subscriberManager.Count())

	// Try to add third subscriber - should fail
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()

	mockStream3 := &mockSubscribePacketsServer{ctx: ctx3}
	req3 := &data.SubscribeRequest{ClientId: "subscriber-3"}

	err = processor.SubscribePackets(req3, mockStream3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ResourceExhausted")
	assert.Contains(t, err.Error(), "maximum number of subscribers")

	// Cleanup
	cancel1()
	cancel2()
	<-done1
	<-done2

	// Verify subscribers were removed
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, processor.subscriberManager.Count())
}

// TestSubscribePackets_AutoGeneratedClientID tests auto-generation of client IDs
func TestSubscribePackets_AutoGeneratedClientID(t *testing.T) {
	// Create processor
	processor, err := New(Config{
		ProcessorID:    "test-processor",
		ListenAddr:     "localhost:50051",
		MaxHunters:     10,
		MaxSubscribers: 10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Create mock stream
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockStream := &mockSubscribePacketsServer{
		ctx: ctx,
	}

	// Create subscribe request without client ID
	req := &data.SubscribeRequest{
		ClientId: "", // Empty - should be auto-generated
	}

	// Run SubscribePackets in goroutine
	done := make(chan error, 1)
	go func() {
		done <- processor.SubscribePackets(req, mockStream)
	}()

	// Wait for subscriber to be registered
	time.Sleep(100 * time.Millisecond)

	// Verify subscriber was added (with auto-generated ID)
	assert.Equal(t, 1, processor.subscriberManager.Count())

	// Cancel context
	cancel()

	// Wait for completion
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("SubscribePackets timed out")
	}
}

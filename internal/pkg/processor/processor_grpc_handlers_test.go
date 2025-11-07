package processor

import (
	"context"
	"fmt"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

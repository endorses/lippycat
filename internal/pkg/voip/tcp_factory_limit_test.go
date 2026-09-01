package voip

import (
	"context"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSipStreamFactory_MaxStreamsCap verifies voip.max_streams rejects new
// streams once the cap is reached, instead of spawning goroutines without bound.
func TestSipStreamFactory_MaxStreamsCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxStreams = 1
	SetConfig(cfg)
	t.Cleanup(ResetConfigCache)

	factory := NewSipStreamFactory(context.Background(), NewLocalFileHandler(TestCallTracker(t))).(*sipStreamFactory)
	defer factory.Shutdown()
	require.Equal(t, 1, factory.config.MaxStreams)

	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint([]byte{10, 0, 0, 1}), layers.NewIPEndpoint([]byte{10, 0, 0, 2}))
	transportFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(5060), layers.NewTCPPortEndpoint(5060))

	first := factory.New(netFlow, transportFlow, &layers.TCP{}, nil)
	assert.IsType(t, &bufferedSIPStream{}, first, "first stream is under the cap")

	second := factory.New(netFlow, transportFlow, &layers.TCP{}, nil)
	assert.IsType(t, &discardStream{}, second, "stream past the cap is discarded")
}

func TestSipStreamFactory_MaxStreamsCapIsAtomicAcrossShards(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxStreams = 2
	SetConfig(cfg)
	t.Cleanup(ResetConfigCache)

	factory := NewSipStreamFactory(context.Background(), NewLocalFileHandler(TestCallTracker(t))).(*sipStreamFactory)
	defer factory.Shutdown()

	netFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint([]byte{10, 0, 0, 1}), layers.NewIPEndpoint([]byte{10, 0, 0, 2}))
	transportFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(5060), layers.NewTCPPortEndpoint(5060))

	const attempts = 32
	start := make(chan struct{})
	results := make(chan reassembly.Stream, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- factory.New(netFlow, transportFlow, &layers.TCP{}, nil)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	accepted := 0
	for stream := range results {
		if _, ok := stream.(*bufferedSIPStream); ok {
			accepted++
		}
	}
	assert.Equal(t, cfg.MaxStreams, accepted)
	assert.Equal(t, int64(cfg.MaxStreams), factory.GetActiveGoroutines())
}

// TestSipStreamFactory_UnlimitedByDefault verifies the cap is opt-in.
func TestSipStreamFactory_UnlimitedByDefault(t *testing.T) {
	ResetConfigCache()
	factory := NewSipStreamFactory(context.Background(), NewLocalFileHandler(TestCallTracker(t))).(*sipStreamFactory)
	defer factory.Shutdown()

	assert.Zero(t, factory.config.MaxStreams)
}

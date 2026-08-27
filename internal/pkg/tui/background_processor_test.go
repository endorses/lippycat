//go:build tui || all

package tui

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestBackgroundProcessorPublishesImmutableTypedResults(t *testing.T) {
	bp := NewBackgroundProcessor()
	t.Cleanup(bp.Stop)

	headers := map[string]string{"Host": "example.test"}
	packet := components.PacketDisplay(types.PacketDisplay{
		Protocol: "HTTP",
		HTTPData: &types.HTTPMetadata{Type: "request", Method: "GET", Headers: headers},
	})
	bp.Submit(packet, 0)
	headers["Host"] = "mutated.test"

	msg := receiveBackgroundResult(t, bp)
	result, ok := msg.(HTTPPacketResultMsg)
	require.True(t, ok)
	require.Equal(t, "example.test", result.Packet.HTTPData.Headers["Host"])
}

func TestBackgroundProcessorStaleGenerationIgnored(t *testing.T) {
	model := NewModel(10, 10, "test", "", nil, false, false, "", false)
	t.Cleanup(model.Shutdown)
	oldGeneration := model.backgroundProcessor.Generation()
	model.backgroundProcessor.Configure(BackgroundProcessorConfig{CaptureMode: components.CaptureModeOffline})

	updated, _ := model.handleDNSPacketResultMsg(DNSPacketResultMsg{
		Generation: oldGeneration,
		Packet:     types.PacketDisplay{Protocol: "DNS", DNSData: &types.DNSMetadata{QueryName: "stale.test"}},
	})
	require.Equal(t, 0, updated.uiState.DNSQueriesView.Count())
}

func TestBackgroundProcessorResultOverflowIsBoundedAndNonBlocking(t *testing.T) {
	bp := NewBackgroundProcessor()
	t.Cleanup(bp.Stop)
	packet := components.PacketDisplay(types.PacketDisplay{
		Protocol: "DNS",
		DNSData:  &types.DNSMetadata{QueryName: "overflow.test"},
	})

	deadline := time.Now().Add(2 * time.Second)
	for bp.ResultDrops() == 0 && time.Now().Before(deadline) {
		for i := 0; i < backgroundQueueSize; i++ {
			bp.Submit(packet, 0)
		}
		time.Sleep(time.Millisecond)
	}
	require.Positive(t, bp.ResultDrops())
	require.LessOrEqual(t, len(bp.resultChan), cap(bp.resultChan))
}

func TestProtocolViewsConcurrentInputRenderedOnEventLoop(t *testing.T) {
	model := NewModel(100, 10, "test", "", nil, false, false, "", false)
	t.Cleanup(model.Shutdown)

	const packetCount = 300
	var submitters sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		submitters.Add(1)
		go func(worker int) {
			defer submitters.Done()
			for i := 0; i < packetCount; i++ {
				switch worker {
				case 0:
					model.backgroundProcessor.Submit(components.PacketDisplay(types.PacketDisplay{Protocol: "DNS", DNSData: &types.DNSMetadata{QueryName: fmt.Sprintf("%d.test", i)}}), 0)
				case 1:
					model.backgroundProcessor.Submit(components.PacketDisplay(types.PacketDisplay{Protocol: "HTTP", SrcIP: "1", DstIP: "2", SrcPort: fmt.Sprint(i), DstPort: "80", HTTPData: &types.HTTPMetadata{Type: "request", Method: "GET"}}), 0)
				case 2:
					model.backgroundProcessor.Submit(components.PacketDisplay(types.PacketDisplay{Protocol: "SMTP", EmailData: &types.EmailMetadata{SessionID: fmt.Sprint(i)}}), 0)
				}
			}
		}(worker)
	}

	submitters.Wait()
	for i := 0; i < packetCount*3; i++ {
		select {
		case msg := <-model.backgroundProcessor.resultChan:
			updated, _ := model.Update(msg)
			model = updated.(Model)
			_ = model.View()
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out after %d results", i)
		}
	}
}

func receiveBackgroundResult(t *testing.T, bp *BackgroundProcessor) interface{} {
	t.Helper()
	select {
	case msg := <-bp.resultChan:
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for background result")
		return nil
	}
}

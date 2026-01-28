package capture

import (
	"os"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/tcpassembly"
)

func TestOfflineFlowIntegration(t *testing.T) {
	files := []string{
		"/home/grischa/Downloads/pcaps/gk_72_rtp_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap",
		"/home/grischa/Downloads/pcaps/gk_72_sip_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap",
	}

	// Check files exist
	for _, path := range files {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("Test file not found: %s", path)
		}
	}

	// Open files and create devices
	var openFiles []*os.File
	var devices []pcaptypes.PcapInterface
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("Error opening %s: %v", path, err)
		}
		openFiles = append(openFiles, f)
		devices = append(devices, pcaptypes.CreateOfflineInterface(f))
	}
	defer func() {
		for _, f := range openFiles {
			f.Close()
		}
	}()

	var packetCount int
	var mu sync.Mutex

	processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
		for pkt := range ch {
			mu.Lock()
			packetCount++
			mu.Unlock()
			_ = pkt
		}
	}

	// Run offline ordered capture
	RunOfflineOrdered(devices, "", processor, nil)

	mu.Lock()
	count := packetCount
	mu.Unlock()

	t.Logf("Received %d packets", count)

	// Expected: 1023 + 54 = 1077
	if count != 1077 {
		t.Errorf("Expected 1077 packets, got %d", count)
	}
}

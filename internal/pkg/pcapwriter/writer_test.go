package pcapwriter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")

	config := &Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 1 * time.Second,
	}

	writer, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, writer)
	defer writer.Close()

	assert.Equal(t, testFile, writer.FilePath())

	// Check file was created
	_, err = os.Stat(testFile)
	assert.NoError(t, err)
}

func TestWritePacket(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")

	config := &Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 100 * time.Millisecond,
	}

	writer, err := New(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create a test packet
	pkt := createTestPacket(t)

	// Write packet
	err = writer.WritePacket(pkt)
	assert.NoError(t, err)

	// Wait for write to complete
	time.Sleep(200 * time.Millisecond)

	// Close writer to flush
	err = writer.Close()
	assert.NoError(t, err)

	// Verify file can be read
	handle, err := pcap.OpenOffline(testFile)
	require.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Read first packet
	select {
	case readPkt := <-packets:
		require.NotNil(t, readPkt)
		assert.Equal(t, len(pkt.Packet.Data()), len(readPkt.Data()))
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout reading packet from PCAP file")
	}
}

func TestWriteMultiplePackets(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_multiple.pcap")

	config := &Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 100 * time.Millisecond,
	}

	writer, err := New(config)
	require.NoError(t, err)
	defer writer.Close()

	numPackets := 10
	for i := 0; i < numPackets; i++ {
		pkt := createTestPacket(t)
		err := writer.WritePacket(pkt)
		assert.NoError(t, err)
	}

	// Wait for writes to complete
	time.Sleep(200 * time.Millisecond)

	// Check stats
	count, bytes := writer.Stats()
	assert.Equal(t, int64(numPackets), count)
	assert.Greater(t, bytes, int64(0))

	// Close and verify
	err = writer.Close()
	assert.NoError(t, err)

	// Read back and count packets
	handle, err := pcap.OpenOffline(testFile)
	require.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	readCount := 0
	timeout := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-packets:
			if pkt == nil {
				// EOF
				assert.Equal(t, numPackets, readCount)
				return
			}
			readCount++
		case <-timeout:
			t.Fatalf("Timeout reading packets, got %d expected %d", readCount, numPackets)
		}
	}
}

func TestCloseIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_close.pcap")

	config := &Config{
		FilePath:     testFile,
		BufferSize:   10,
		SyncInterval: 1 * time.Second,
	}

	writer, err := New(config)
	require.NoError(t, err)

	// Close multiple times should not error
	err = writer.Close()
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)
}

func TestWriteAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_write_after_close.pcap")

	config := &Config{
		FilePath:     testFile,
		BufferSize:   10,
		SyncInterval: 1 * time.Second,
	}

	writer, err := New(config)
	require.NoError(t, err)

	// Close writer
	err = writer.Close()
	assert.NoError(t, err)

	// Try to write after close
	pkt := createTestPacket(t)
	err = writer.WritePacket(pkt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestEmptyFilePath(t *testing.T) {
	config := &Config{
		FilePath:     "",
		BufferSize:   10,
		SyncInterval: 1 * time.Second,
	}

	writer, err := New(config)
	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "file path cannot be empty")
}

func TestDefaultConfig(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_default.pcap")

	config := DefaultConfig()
	config.FilePath = testFile

	writer, err := New(config)
	require.NoError(t, err)
	defer writer.Close()

	assert.Equal(t, testFile, writer.FilePath())
}

func TestNilConfig(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_nil_config.pcap")

	// Should use default config but fail because no file path
	writer, err := New(nil)
	assert.Error(t, err)
	assert.Nil(t, writer)

	// Now with file path set in default config manually
	config := DefaultConfig()
	config.FilePath = testFile
	writer, err = New(config)
	require.NoError(t, err)
	defer writer.Close()
	assert.NotNil(t, writer)
}

// Helper functions

func createTestPacket(t *testing.T) capture.PacketInfo {
	// Create a simple UDP packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Ethernet layer
	ethLayer := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP layer
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// UDP layer
	udpLayer := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Payload
	payload := gopacket.Payload([]byte("Test packet data"))

	err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, payload)
	require.NoError(t, err)

	// Create packet
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}

	return capture.PacketInfo{
		LinkType:  layers.LinkTypeEthernet,
		Packet:    packet,
		Interface: "test0",
	}
}

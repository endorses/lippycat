package voip

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func testOutputPacket() gopacket.Packet {
	data := make([]byte, 64)
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo.Timestamp = time.Now()
	p.Metadata().CaptureInfo.CaptureLength = len(data)
	p.Metadata().CaptureInfo.Length = len(data)
	return p
}

func TestSessionOutputManagerLifecycleAndPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.OutputFile = filepath.Join(dir, "capture.pcap")
	m := NewSessionOutputManager(cfg)
	require.NoError(t, m.OpenSession("call-one", layers.LinkTypeEthernet))
	require.NoError(t, m.WritePacket("call-one", testOutputPacket(), PacketTypeSIP))
	require.NoError(t, m.WritePacket("call-one", testOutputPacket(), PacketTypeRTP))
	require.NoError(t, m.CloseSession("call-one"))
	require.ErrorIs(t, m.WritePacket("call-one", testOutputPacket(), PacketTypeSIP), ErrWriterNotInitialized)

	for _, name := range []string{"capture_sip_call-one.pcap", "capture_rtp_call-one.pcap"} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestSessionOutputManagerConcurrentWriteAndClose(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputFile = filepath.Join(t.TempDir(), "capture.pcap")
	m := NewSessionOutputManager(cfg)
	require.NoError(t, m.OpenSession("race", layers.LinkTypeEthernet))
	p := testOutputPacket()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				err := m.WritePacket("race", p, PacketTypeSIP)
				if err != nil && err != ErrWriterNotInitialized {
					t.Errorf("unexpected write error: %v", err)
					return
				}
			}
		}()
	}
	require.NoError(t, m.CloseSession("race"))
	wg.Wait()
	require.NoError(t, m.Shutdown())
}

func TestSessionOutputManagerShutdownIsTerminalAndIdempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputFile = filepath.Join(t.TempDir(), "capture.pcap")
	m := NewSessionOutputManager(cfg)
	require.NoError(t, m.OpenSession("shutdown", layers.LinkTypeEthernet))
	require.NoError(t, m.Shutdown())
	require.NoError(t, m.Shutdown())
	require.ErrorIs(t, m.OpenSession("later", layers.LinkTypeEthernet), ErrOutputManagerClosed)
	require.ErrorIs(t, m.WritePacket("shutdown", testOutputPacket(), PacketTypeSIP), ErrOutputManagerClosed)
}

func TestSessionOutputManagerReplayReopensWithoutTruncating(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputFile = filepath.Join(t.TempDir(), "capture.pcap")
	manager := NewSessionOutputManager(cfg)
	manager.replayFiles = make(map[string]layers.LinkType)
	packet := testOutputPacket()
	for range 2 {
		require.NoError(t, manager.OpenSession("repeat", layers.LinkTypeEthernet))
		require.NoError(t, manager.WritePacket("repeat", packet, PacketTypeSIP))
		require.NoError(t, manager.WritePacket("repeat", packet, PacketTypeRTP))
		require.NoError(t, manager.CloseSession("repeat"))
	}
	require.NoError(t, manager.Shutdown())
	for _, kind := range []string{"sip", "rtp"} {
		file, err := os.Open(filepath.Join(filepath.Dir(cfg.OutputFile), "capture_"+kind+"_repeat.pcap"))
		require.NoError(t, err)
		reader, err := pcapgo.NewReader(file)
		require.NoError(t, err)
		for range 2 {
			data, _, err := reader.ReadPacketData()
			require.NoError(t, err)
			require.Equal(t, packet.Data(), data)
		}
		_, _, err = reader.ReadPacketData()
		require.ErrorIs(t, err, io.EOF)
		require.NoError(t, file.Close())
	}
}

func TestSessionOutputManagerReplayRejectsChangedLinkType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputFile = filepath.Join(t.TempDir(), "capture.pcap")
	manager := NewSessionOutputManager(cfg)
	manager.replayFiles = make(map[string]layers.LinkType)
	require.NoError(t, manager.OpenSession("repeat", layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseSession("repeat"))
	require.ErrorContains(t, manager.OpenSession("repeat", layers.LinkTypeRaw), "cannot append replay call")
	require.NoError(t, manager.Shutdown())
}

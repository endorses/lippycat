//go:build cli || all
// +build cli all

package voip

import (
	"context"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
)

func StartVoipSniffer(devices []pcaptypes.PcapInterface, filter string) {
	ctx := context.Background()
	logger.InfoContext(ctx, "Starting VoIP sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Create handler for local file writing
	handler := NewLocalFileHandler()
	streamFactory := NewSipStreamFactory(ctx, handler)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Detect offline mode (reading from PCAP file)
	// Offline interfaces have filenames as their Name(), not network interface names
	isOffline := false
	for _, dev := range devices {
		// Offline interfaces return the filename in Name()
		// which will contain a path separator or .pcap extension
		name := dev.Name()
		if strings.Contains(name, ".pcap") || strings.Contains(name, ".pcapng") || strings.Contains(name, "/") {
			isOffline = true
			break
		}
	}

	if isOffline {
		// For offline mode, run until PCAP is fully read
		capture.RunOffline(devices, filter, startProcessor, assembler)
	} else {
		// For live mode, run with signal handler (waits for Ctrl+C)
		capture.RunWithSignalHandler(devices, filter, startProcessor, assembler)
	}
}

func StartLiveVoipSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, StartVoipSniffer)
}

func StartOfflineVoipSniffer(interfaces, filter string) {
	capture.StartOfflineSniffer(interfaces, filter, StartVoipSniffer)
}

func startProcessor(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
	defer CloseWriters()

	// Initialize buffer manager (5 second timeout, 200 packet max per call)
	bufferOnce.Do(func() {
		globalBufferMgr = NewBufferManager(5*time.Second, 200)
		logger.Info("Initialized VoIP buffer manager", "max_age", "5s", "max_size", 200)
	})
	defer func() {
		if globalBufferMgr != nil {
			globalBufferMgr.Close()
		}
	}()

	// Initialize virtual interface if enabled
	if viper.GetBool("voip.virtual_interface") {
		vifName := viper.GetString("voip.vif_name")
		if vifName == "" {
			vifName = "lc0"
		}

		cfg := vinterface.DefaultConfig()
		cfg.Name = vifName

		var err error
		globalVifMgr, err = vinterface.NewManager(cfg)
		if err != nil {
			logger.Error("Failed to create virtual interface manager",
				"error", err,
				"interface_name", vifName)
			logger.Warn("Continuing without virtual interface")
		} else {
			err = globalVifMgr.Start()
			if err != nil {
				logger.Error("Failed to start virtual interface",
					"error", err,
					"interface_name", vifName)
				logger.Warn("Continuing without virtual interface")
				globalVifMgr = nil
			} else {
				logger.Info("Virtual interface started successfully",
					"interface_name", globalVifMgr.Name())
				defer func() {
					if globalVifMgr != nil {
						stats := globalVifMgr.Stats()
						logger.Info("Virtual interface statistics",
							"packets_injected", stats.PacketsInjected,
							"packets_dropped", stats.PacketsDropped,
							"injection_errors", stats.InjectionErrors,
							"conversion_errors", stats.ConversionErrors)
						if err := globalVifMgr.Shutdown(); err != nil {
							logger.Error("Error shutting down virtual interface", "error", err)
						} else {
							logger.Info("Virtual interface shutdown successfully")
						}
					}
				}()
			}
		}
	}

	packetCount := 0
	for pkt := range ch {
		packetCount++
		logger.Debug("VoIP processor received packet", "count", packetCount, "has_network", pkt.Packet.NetworkLayer() != nil, "has_transport", pkt.Packet.TransportLayer() != nil)
		packet := pkt.Packet
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			logger.Debug("Skipping packet - missing network or transport layer")
			continue
		}

		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			logger.Debug("Processing TCP packet")
			handleTcpPackets(pkt, layer, assembler)
		case *layers.UDP:
			logger.Debug("Processing UDP packet")
			handleUdpPackets(pkt, layer)
		}
	}

	// Flush and close all TCP streams
	// This is critical for offline mode where streams may not be closed with FIN/RST
	if assembler != nil {
		logger.Debug("Flushing and closing TCP assembler streams")
		// Use FlushOlderThan with time.Now() to close ALL streams regardless of age
		// This signals EOF to all stream readers so they stop blocking and process their buffers
		flushed, closed := assembler.FlushOlderThan(time.Now())
		logger.Debug("TCP streams flushed", "flushed", flushed, "closed", closed)

		// Give stream goroutines time to process and finish
		time.Sleep(200 * time.Millisecond)
	}

	logger.Info("VoIP processor finished", "total_packets", packetCount)
}

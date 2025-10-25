//go:build cli || all
// +build cli all

package voip

import (
	"context"
	"errors"
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

	// Initialize virtual interface FIRST if enabled (before processing any packets)
	// This allows early permission check and avoids wasting time processing packets
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
			// Provide helpful error message for permission errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
				logger.Error("Aborting - cannot proceed without virtual interface when --virtual-interface flag is set")
				return
			} else {
				logger.Error("Failed to create virtual interface manager",
					"error", err,
					"interface_name", vifName)
				logger.Error("Aborting - cannot proceed without virtual interface when --virtual-interface flag is set")
				return
			}
		}

		err = globalVifMgr.Start()
		if err != nil {
			// Provide helpful error message for permission errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else {
				logger.Error("Failed to start virtual interface",
					"error", err,
					"interface_name", vifName)
			}
			logger.Error("Aborting - cannot proceed without virtual interface when --virtual-interface flag is set")
			return
		}

		logger.Info("Virtual interface started successfully",
			"interface_name", globalVifMgr.Name())

		// Wait for external tools (tcpdump, Wireshark) to attach
		startupDelay := viper.GetDuration("voip.vif_startup_delay")
		if startupDelay > 0 {
			logger.Info("Waiting for monitoring tools to attach...",
				"delay", startupDelay)
			time.Sleep(startupDelay)
		}
		logger.Info("Starting packet injection")

		// Ensure cleanup on exit
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

	// Note: Virtual interface is now initialized in StartVoipSniffer() before packet processing begins
	// This allows early permission checking and avoids wasting time if permissions are insufficient

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

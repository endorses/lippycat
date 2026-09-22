//go:build hunter || all

package hunt

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/viper"
)

// hunterConfigSpec contains the protocol-specific differences in the otherwise
// common hunter transport configuration.
type hunterConfigSpec struct {
	protocol            protocolcatalog.Spec
	bpfFilter           string
	voIPMode            bool
	enableVoIPFilter    bool
	useGPUFlag          bool
	includeDiskBuffer   bool
	includeFilterPolicy bool
}

// protocolHunterConfigSpec adapts a shared protocol registration to the hunter
// topology. Protocol command files only resolve flags and analyzer callbacks.
func protocolHunterConfigSpec(name, bpfFilter string) hunterConfigSpec {
	protocol := protocolcatalog.MustLookup(name)
	return hunterConfigSpec{
		protocol:            protocol,
		bpfFilter:           bpfFilter,
		voIPMode:            protocol.Hunter.VoIPMode,
		enableVoIPFilter:    protocol.Hunter.EnableVoIPFilter,
		useGPUFlag:          protocol.Hunter.UseGPUConfig,
		includeDiskBuffer:   protocol.Hunter.IncludeDiskBuffer,
		includeFilterPolicy: protocol.Hunter.IncludeFilterPolicy,
	}
}

func buildHunterConfig(spec hunterConfigSpec) hunter.Config {
	config := hunter.Config{
		ProcessorAddr:              cmdutil.GetStringConfig("hunter.processor_addr", processorAddr),
		HunterID:                   cmdutil.GetStringConfig("hunter.hunter_id", hunterID),
		Interfaces:                 cmdutil.GetStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:                  spec.bpfFilter,
		BufferSize:                 cmdutil.GetIntConfig("hunter.buffer_size", bufferSize),
		SIPBufferSize:              cmdutil.GetIntConfig("hunter.sip_buffer_size", sipBufferSize),
		BatchSize:                  cmdutil.GetIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:               time.Duration(cmdutil.GetIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize:             cmdutil.GetIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:                   spec.voIPMode,
		EnableVoIPFilter:           spec.enableVoIPFilter,
		SupportedFilterTypes:       append([]string(nil), spec.protocol.SupportedFilterTypes...),
		TLSEnabled:                 !cmdutil.GetBoolConfig("insecure", insecureAllowed),
		TLSCertFile:                cmdutil.GetStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:                 cmdutil.GetStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:                  cmdutil.GetStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify:              cmdutil.GetBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
		ForwardMode:                strings.ToLower(viper.GetString("hunter.forward_mode")),
		EventFallbackToPackets:     viper.GetBool("hunter.events.fallback_to_packets"),
		EventDeliveryProfile:       strings.ReplaceAll(strings.ToLower(viper.GetString("hunter.events.delivery_profile")), "-", "_"),
		EventSpoolDir:              viper.GetString("hunter.events.spool.dir"),
		EventSpoolMaxBytes:         viper.GetUint64("hunter.events.spool.max_bytes"),
		EventSpoolMaxAge:           viper.GetDuration("hunter.events.spool.max_age"),
		EventSpoolExhaustionPolicy: strings.ToLower(viper.GetString("hunter.events.spool.exhaustion_policy")),
	}

	if spec.useGPUFlag {
		gpu := GetGPUConfig()
		config.GPUBackend = gpu.GPUBackend
		config.GPUBatchSize = gpu.GPUBatchSize
		if !spec.enableVoIPFilter {
			config.EnableVoIPFilter = gpu.EnableVoIPFilter
		}
	}
	if spec.includeDiskBuffer {
		config.DiskBufferEnabled = cmdutil.GetBoolConfig("hunter.disk_buffer.enabled", diskBufferEnabled)
		config.DiskBufferDir = cmdutil.GetStringConfig("hunter.disk_buffer.dir", diskBufferDir)
		config.DiskBufferMaxSize = uint64(cmdutil.GetIntConfig("hunter.disk_buffer.max_mb", diskBufferMaxSize)) * 1024 * 1024
	}
	if spec.includeFilterPolicy {
		config.NoFilterPolicy = cmdutil.GetStringConfig("hunter.no_filter_policy", noFilterPolicy)
	}
	return config
}

func buildHunterConfigChecked(spec hunterConfigSpec) (hunter.Config, error) {
	config := buildHunterConfig(spec)
	sipCapacity, err := cmdutil.GetIntConfigStrict("hunter.sip_buffer_size", sipBufferSize)
	if err != nil {
		return hunter.Config{}, err
	}
	config.SIPBufferSize = sipCapacity
	return config, nil
}

func validateHunterForwardingConfig(config hunter.Config) error {
	if config.SIPBufferSize < 0 {
		return fmt.Errorf("hunter.sip_buffer_size must be non-negative, got %d", config.SIPBufferSize)
	}
	if config.ForwardMode == "" {
		config.ForwardMode = "packets"
	}
	if config.EventDeliveryProfile == "" {
		config.EventDeliveryProfile = "reliable"
	}
	if config.EventSpoolExhaustionPolicy == "" {
		config.EventSpoolExhaustionPolicy = "drop_oldest"
	}
	if config.ForwardMode != "packets" && config.ForwardMode != "events" {
		return fmt.Errorf("invalid forward mode %q: must be packets or events", config.ForwardMode)
	}
	if config.EventDeliveryProfile != "reliable" && config.EventDeliveryProfile != "memory_only" {
		return fmt.Errorf("invalid event delivery profile %q: must be reliable or memory-only", config.EventDeliveryProfile)
	}
	if config.EventSpoolExhaustionPolicy != "drop_oldest" && config.EventSpoolExhaustionPolicy != "drop_new" {
		return fmt.Errorf("invalid event spool exhaustion policy %q: must be drop_oldest or drop_new", config.EventSpoolExhaustionPolicy)
	}
	if config.EventFallbackToPackets && config.ForwardMode != "events" {
		return fmt.Errorf("event fallback to packets is only valid with --forward-mode=events")
	}
	if config.ForwardMode == "events" && config.EventDeliveryProfile == "reliable" && config.EventSpoolDir == "" {
		return fmt.Errorf("reliable event delivery requires a non-empty event spool directory")
	}
	return nil
}

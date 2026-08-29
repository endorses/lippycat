//go:build hunter || all

package hunt

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
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
		ProcessorAddr:        cmdutil.GetStringConfig("hunter.processor_addr", processorAddr),
		HunterID:             cmdutil.GetStringConfig("hunter.hunter_id", hunterID),
		Interfaces:           cmdutil.GetStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:            spec.bpfFilter,
		BufferSize:           cmdutil.GetIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:            cmdutil.GetIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:         time.Duration(cmdutil.GetIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize:       cmdutil.GetIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:             spec.voIPMode,
		EnableVoIPFilter:     spec.enableVoIPFilter,
		SupportedFilterTypes: append([]string(nil), spec.protocol.SupportedFilterTypes...),
		TLSEnabled:           !cmdutil.GetBoolConfig("insecure", insecureAllowed),
		TLSCertFile:          cmdutil.GetStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:           cmdutil.GetStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:            cmdutil.GetStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify:        cmdutil.GetBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
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

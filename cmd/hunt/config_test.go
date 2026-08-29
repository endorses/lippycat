//go:build hunter || all

package hunt

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHunterConfigProtocolFixtures(t *testing.T) {
	processorAddr = "processor.example:55555"
	hunterID = "edge-01"
	interfaces = []string{"eth0", "eth1"}
	bufferSize = 1234
	batchSize = 42
	batchTimeout = 75
	batchQueueSize = 91
	insecureAllowed = false
	tlsCertFile = "client.crt"
	tlsKeyFile = "client.key"
	tlsCAFile = "ca.crt"
	tlsSkipVerify = false
	noFilterPolicy = "deny"
	diskBufferEnabled = true
	diskBufferDir = "/var/tmp/lippycat-test-buffer"
	diskBufferMaxSize = 17

	tests := []struct {
		name               string
		specForCommand     func(string) hunterConfigSpec
		wantVoIP           bool
		wantVoIPFilter     bool
		wantFilterTypes    []string
		wantDiskBuffer     bool
		wantNoFilterPolicy string
	}{
		{name: "dns", specForCommand: dnsHunterConfigSpec, wantFilterTypes: []string{"bpf", "ip_address", "dns_domain"}},
		{name: "http", specForCommand: httpHunterConfigSpec, wantFilterTypes: []string{"bpf", "ip_address", "http_host", "http_path"}},
		{name: "tls", specForCommand: tlsHunterConfigSpec, wantFilterTypes: []string{"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"}},
		{name: "email", specForCommand: emailHunterConfigSpec, wantFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"}},
		{name: "voip", specForCommand: voipHunterConfigSpec, wantVoIP: true, wantVoIPFilter: true, wantNoFilterPolicy: "deny"},
		{name: "generic", specForCommand: genericHunterConfigSpec, wantDiskBuffer: true, wantNoFilterPolicy: "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterFixture := tt.name + "-filter"
			spec := tt.specForCommand(filterFixture)
			if tt.name != "generic" {
				assert.Equal(t, protocolcatalog.MustLookup(tt.name), spec.protocol)
			}
			config := buildHunterConfig(spec)
			require.Equal(t, "processor.example:55555", config.ProcessorAddr)
			assert.Equal(t, "edge-01", config.HunterID)
			assert.Equal(t, []string{"eth0", "eth1"}, config.Interfaces)
			assert.Equal(t, filterFixture, config.BPFFilter)
			assert.Equal(t, 1234, config.BufferSize)
			assert.Equal(t, 42, config.BatchSize)
			assert.Equal(t, 75*time.Millisecond, config.BatchTimeout)
			assert.Equal(t, 91, config.BatchQueueSize)
			assert.Equal(t, tt.wantVoIP, config.VoIPMode)
			assert.Equal(t, tt.wantVoIPFilter, config.EnableVoIPFilter)
			assert.Equal(t, tt.wantFilterTypes, config.SupportedFilterTypes)
			assert.True(t, config.TLSEnabled)
			assert.Equal(t, "client.crt", config.TLSCertFile)
			assert.Equal(t, "client.key", config.TLSKeyFile)
			assert.Equal(t, "ca.crt", config.TLSCAFile)
			assert.Equal(t, tt.wantDiskBuffer, config.DiskBufferEnabled)
			assert.Equal(t, tt.wantNoFilterPolicy, config.NoFilterPolicy)
			if tt.wantDiskBuffer {
				assert.Equal(t, "/var/tmp/lippycat-test-buffer", config.DiskBufferDir)
				assert.Equal(t, uint64(17*1024*1024), config.DiskBufferMaxSize)
			}
		})
	}
}

func TestBuildHunterConfigCopiesFilterCapabilities(t *testing.T) {
	filterTypes := []string{"bpf", "dns_domain"}
	config := buildHunterConfig(hunterConfigSpec{protocol: protocolcatalog.Spec{SupportedFilterTypes: filterTypes}})
	filterTypes[1] = "changed"
	assert.Equal(t, []string{"bpf", "dns_domain"}, config.SupportedFilterTypes)
}

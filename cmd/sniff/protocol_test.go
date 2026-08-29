//go:build cli || all

package sniff

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSniffRuntimeHooksValidate(t *testing.T) {
	protocol := protocolcatalog.Spec{Name: "test", Analyzer: "test"}
	valid := sniffRuntimeHooks{
		BuildBPF:   func(string) (string, error) { return "", nil },
		StartLive:  func(string, string) {},
		StartFiles: func([]string, string) {},
	}
	require.NoError(t, valid.validate(protocol))

	tests := []struct {
		name string
		edit func(*sniffRuntimeHooks)
	}{
		{name: "builder", edit: func(s *sniffRuntimeHooks) { s.BuildBPF = nil }},
		{name: "live", edit: func(s *sniffRuntimeHooks) { s.StartLive = nil }},
		{name: "files", edit: func(s *sniffRuntimeHooks) { s.StartFiles = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := valid
			tt.edit(&spec)
			require.Error(t, spec.validate(protocol))
		})
	}
}

func TestProtocolCommandsUseSharedCatalog(t *testing.T) {
	t.Parallel()

	for name, got := range map[string]sniffRuntimeHooks{
		"dns": dnsRuntimeHooks, "email": emailRuntimeHooks, "http": httpRuntimeHooks, "tls": tlsRuntimeHooks, "voip": voipRuntimeHooks,
	} {
		require.NoError(t, got.validate(protocolcatalog.MustLookup(name)))
	}
}

func TestRunProtocolSelectsIngressAndPreservesArguments(t *testing.T) {
	originalReadFile, originalInterfaces, originalFilter := readFile, interfaces, filter
	t.Cleanup(func() { readFile, interfaces, filter = originalReadFile, originalInterfaces, originalFilter })
	interfaces, filter = "eth-test", "tcp"

	var liveCalls int
	var gotInterfaces, gotFilter string
	var gotFiles []string
	protocol := protocolcatalog.Spec{Name: "test", Analyzer: "test"}
	hooks := sniffRuntimeHooks{
		BuildBPF: func(base string) (string, error) {
			require.Equal(t, "tcp", base)
			return "tcp and port 42", nil
		},
		StartLive: func(ifaces, bpf string) {
			liveCalls++
			gotInterfaces, gotFilter = ifaces, bpf
		},
		StartFiles: func(files []string, bpf string) {
			gotFiles, gotFilter = files, bpf
		},
	}

	readFile = ""
	runProtocol(&cobra.Command{}, nil, protocol, hooks)
	require.Equal(t, 1, liveCalls)
	require.Equal(t, "eth-test", gotInterfaces)
	require.Equal(t, "tcp and port 42", gotFilter)

	readFile = "first.pcap"
	runProtocol(&cobra.Command{}, []string{"second.pcap"}, protocol, hooks)
	require.Equal(t, []string{"first.pcap", "second.pcap"}, gotFiles)
	require.Equal(t, "tcp and port 42", gotFilter)
}

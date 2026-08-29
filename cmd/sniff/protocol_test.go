//go:build cli || all

package sniff

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestProtocolSpecValidate(t *testing.T) {
	valid := ProtocolSpec{
		Spec:       protocolcatalog.Spec{Name: "test"},
		BuildBPF:   func(string) (string, error) { return "", nil },
		StartLive:  func(string, string) {},
		StartFiles: func([]string, string) {},
	}
	require.NoError(t, valid.validate())

	tests := []struct {
		name string
		edit func(*ProtocolSpec)
	}{
		{name: "name", edit: func(s *ProtocolSpec) { s.Name = "" }},
		{name: "builder", edit: func(s *ProtocolSpec) { s.BuildBPF = nil }},
		{name: "live", edit: func(s *ProtocolSpec) { s.StartLive = nil }},
		{name: "files", edit: func(s *ProtocolSpec) { s.StartFiles = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := valid
			tt.edit(&spec)
			require.Error(t, spec.validate())
		})
	}
}

func TestProtocolCommandsUseSharedCatalog(t *testing.T) {
	t.Parallel()

	for name, got := range map[string]ProtocolSpec{
		"dns": dnsSpec, "email": emailSpec, "http": httpSpec, "tls": tlsSpec, "voip": voipSpec,
	} {
		require.Equal(t, protocolcatalog.MustLookup(name), got.Spec)
	}
}

func TestRunProtocolSelectsIngressAndPreservesArguments(t *testing.T) {
	originalReadFile, originalInterfaces, originalFilter := readFile, interfaces, filter
	t.Cleanup(func() { readFile, interfaces, filter = originalReadFile, originalInterfaces, originalFilter })
	interfaces, filter = "eth-test", "tcp"

	var liveCalls int
	var gotInterfaces, gotFilter string
	var gotFiles []string
	spec := ProtocolSpec{
		Spec: protocolcatalog.Spec{Name: "test"},
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
	runProtocol(&cobra.Command{}, nil, spec)
	require.Equal(t, 1, liveCalls)
	require.Equal(t, "eth-test", gotInterfaces)
	require.Equal(t, "tcp and port 42", gotFilter)

	readFile = "first.pcap"
	runProtocol(&cobra.Command{}, []string{"second.pcap"}, spec)
	require.Equal(t, []string{"first.pcap", "second.pcap"}, gotFiles)
	require.Equal(t, "tcp and port 42", gotFilter)
}

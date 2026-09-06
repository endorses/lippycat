package eventanalysis

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestReassemblyNamespaceCachePreservesSourceHash(t *testing.T) {
	r := &Runtime{}
	sources := []Source{
		{}, {NodeID: "node"}, {CaptureSource: "pcap"}, {InterfaceName: "eth0"},
		{InterfaceIndex: 12345}, {InterfaceIndex: ^uint32(0)}, {InputFile: "/tmp/capture.pcap"},
		{NodeID: "node", CaptureSource: "pcap", InterfaceName: "eth0", InterfaceIndex: 12, InputFile: "capture.pcap"},
		{NodeID: "node\x00name", InputFile: "file\x00name"},
		{},
	}
	for _, source := range sources {
		legacyBytes := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00", source.NodeID, source.CaptureSource, source.InterfaceName, source.InterfaceIndex, source.InputFile)
		digest := sha256.Sum256([]byte(legacyBytes))
		want := binary.BigEndian.Uint64(digest[:])
		require.Equal(t, want, sourceNamespace(source))
		require.Equal(t, want, r.cachedSourceNamespace(source))
		require.Equal(t, want, r.cachedSourceNamespace(source), "cache hit")
		source.Partial = true
		source.ProcessorNodeIDs = []string{"upstream"}
		require.Equal(t, want, r.cachedSourceNamespace(source), "unhashed context must not change identity")
	}
}

func TestNamespacedEndpointMatchesLegacyDigest(t *testing.T) {
	for _, endpoint := range []gopacket.Endpoint{
		gopacket.NewEndpoint(layers.EndpointIPv4, net.ParseIP("192.0.2.1").To4()),
		gopacket.NewEndpoint(layers.EndpointIPv6, net.ParseIP("2001:db8::1").To16()),
		gopacket.NewEndpoint(layers.EndpointTCPPort, []byte{0, 80}),
		gopacket.InvalidEndpoint,
	} {
		for _, namespace := range []uint64{0, 12345, ^uint64(0)} {
			legacy := make([]byte, 16)
			binary.BigEndian.PutUint64(legacy, namespace)
			binary.BigEndian.PutUint64(legacy[8:], uint64(endpoint.EndpointType()))
			legacy = append(legacy, endpoint.Raw()...)
			digest := sha256.Sum256(legacy)
			actual := namespacedEndpoint(namespace, endpoint)
			require.Equal(t, digest[:16], actual[:])
		}
	}
}

func TestTypedReassemblyKeyPreservesBidirectionalSeparation(t *testing.T) {
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	ports := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 80}, []byte{0x9c, 0x40})
	key := canonicalReassemblyFlowKey(7, network, ports)
	require.Equal(t, key, canonicalReassemblyFlowKey(7, network.Reverse(), ports.Reverse()))
	require.NotEqual(t, key, canonicalReassemblyFlowKey(8, network, ports))
	require.NotEqual(t, key, canonicalReassemblyFlowKey(7, network, ports.Reverse()))
	self := gopacket.NewFlow(layers.EndpointIPv4, []byte{127, 0, 0, 1}, []byte{127, 0, 0, 1})
	require.Equal(t, canonicalReassemblyFlowKey(7, self, ports), canonicalReassemblyFlowKey(7, self, ports.Reverse()))
}

func BenchmarkReassemblyIdentity(b *testing.B) {
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	ports := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 80}, []byte{0x9c, 0x40})
	source := Source{NodeID: "node", CaptureSource: "pcap", InputFile: "/tmp/capture.pcap"}
	r := &Runtime{}
	b.ReportAllocs()
	for range b.N {
		namespace := r.cachedSourceNamespace(source)
		key := canonicalReassemblyFlowKey(namespace, network, ports)
		endpoint := namespacedEndpoint(namespace, network.Src())
		if key.namespace != namespace || endpoint == [16]byte{} {
			b.Fatal("invalid identity")
		}
	}
}

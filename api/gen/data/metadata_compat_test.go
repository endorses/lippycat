package data

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTLSHTTPMetadataWireCompatibilityAndSize(t *testing.T) {
	base := &PacketBatch{HunterId: "old", Packets: []*CapturedPacket{{Metadata: &PacketMetadata{SrcIp: "192.0.2.1", DstIp: "192.0.2.2", SrcPort: 50000, DstPort: 80, Transport: "tcp"}}}}
	baseBytes, err := proto.Marshal(base)
	require.NoError(t, err)
	withMetadata := proto.Clone(base).(*PacketBatch)
	withMetadata.Packets[0].Metadata.Http = &HTTPMetadata{Method: "GET", Path: "/", Host: "example.test"}
	withoutHeaders, err := proto.Marshal(withMetadata)
	require.NoError(t, err)
	withMetadata.Packets[0].Metadata.Http.Headers = map[string]string{"user-agent": "test", "accept": "*/*"}
	withHeaders, err := proto.Marshal(withMetadata)
	require.NoError(t, err)
	t.Logf("protobuf batch bytes: base=%d http=%d http_with_headers=%d", len(baseBytes), len(withoutHeaders), len(withHeaders))
	require.Greater(t, len(withoutHeaders), len(baseBytes))
	require.Greater(t, len(withHeaders), len(withoutHeaders))
	var decoded PacketBatch
	require.NoError(t, proto.Unmarshal(baseBytes, &decoded))
	require.Nil(t, decoded.Packets[0].Metadata.Tls)
	require.Nil(t, decoded.Packets[0].Metadata.Http)
}

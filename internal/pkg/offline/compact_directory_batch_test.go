package offline

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactDirectoryBatchAuthenticatesAllRows(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	ctx := context.Background()
	const count = compactRows*2 + 3
	for i := 0; i < count; i++ {
		detail.Source.Sequence = uint64(i)
		// Exercise absent, changing and shared summary-block references alongside
		// sparse metadata references, including both sides of block boundaries.
		detail.Packet.TLSData = nil
		if i%3 == 0 {
			detail.Packet.TLSData = &types.TLSMetadata{SNI: "directory.example"}
		}
		require.NoError(t, b.AppendCompact(ctx, detail, provenance))
	}
	dataset, err := b.Finish(ctx)
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	defer func() { require.NoError(t, d.Close()) }()
	stat, err := d.offsets.Stat()
	require.NoError(t, err)
	require.EqualValues(t, compactHeaderBytes+count*compactIndexBytes, stat.Size())
	for id := PacketID(0); id < count; id++ {
		var entry [compactIndexBytes]byte
		_, err := d.offsets.ReadAt(entry[:], compactHeaderBytes+int64(id)*compactIndexBytes)
		require.NoError(t, err)
		// The independent random-access checksum path reads the authoritative
		// headers afresh, checking byte compatibility with the batched writer.
		want, err := d.compactIndexChecksum(entry[:32], id)
		require.NoError(t, err)
		require.Equal(t, want[:], entry[32:])
		require.GreaterOrEqual(t, binary.LittleEndian.Uint64(entry[:8]), uint64(compactHeaderBytes))
		got, err := d.Detail(ctx, Token{Dataset: 17}, id)
		require.NoError(t, err)
		require.EqualValues(t, id, got.Source.Sequence)
		if id%3 == 0 {
			require.Equal(t, "directory.example", got.Packet.TLSData.SNI)
		} else {
			require.Nil(t, got.Packet.TLSData)
		}
	}
}

func TestCompactDetailMemoryMatchesGenericAccounting(t *testing.T) {
	_, _, detail, _ := compactReviewBuilder(t)
	detail.Packet.VoIPData = &types.VoIPMetadata{Headers: map[string]string{"From": "alice"}, RawSIP: []byte{1, 2}, AccessNetworkInfo: &types.AccessNetworkInfo{Parameters: map[string]string{"cell": "test"}}}
	detail.Packet.DNSData = &types.DNSMetadata{Answers: []types.DNSAnswer{{Data: "192.0.2.1"}}}
	detail.Packet.EmailData = &types.EmailMetadata{RcptTo: []string{"recipient"}}
	detail.Packet.TLSData = &types.TLSMetadata{CipherSuites: []uint16{1, 2}, ALPNProtocols: []string{"h2"}}
	detail.Packet.HTTPData = &types.HTTPMetadata{Headers: map[string]string{}}
	for _, value := range []Detail{{}, detail} {
		want, err := compactRecordMemory(&value, 1<<20)
		require.NoError(t, err)
		got, err := compactDetailMemory(&value, 1<<20)
		require.NoError(t, err)
		require.Equal(t, want, got)
		_, err = compactDetailMemory(&value, want)
		require.NoError(t, err)
		_, err = compactDetailMemory(&value, want-1)
		require.Error(t, err)
	}
}

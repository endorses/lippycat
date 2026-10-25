package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func pcapRecord(size uint32) []byte {
	data := make([]byte, 40)
	copy(data, []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0})
	binary.LittleEndian.PutUint32(data[16:20], ^uint32(0))
	binary.LittleEndian.PutUint32(data[20:24], 1) // Ethernet
	binary.LittleEndian.PutUint32(data[32:36], size)
	binary.LittleEndian.PutUint32(data[36:40], size)
	return data
}

type payloadGuard struct {
	header     *bytes.Reader
	unexpected int
}

func (g *payloadGuard) Read(p []byte) (int, error) {
	if g.header.Len() == 0 {
		g.unexpected++
		return 0, errors.New("payload must not be requested")
	}
	return g.header.Read(p)
}

func TestOversizedRecordRejectedBeforePayloadRead(t *testing.T) {
	for _, n := range []uint32{maxRecordBytes + 1, ^uint32(0)} {
		guard := &payloadGuard{header: bytes.NewReader(pcapRecord(n))}
		result, err := summarize(guard)
		require.ErrorContains(t, err, "capture length exceeds snap length")
		require.Zero(t, result.Packets)
		require.Zero(t, guard.unexpected)
	}
}

func TestMaxSnaplenPreservesOrdinaryRecords(t *testing.T) {
	data := append(pcapRecord(60), make([]byte, 60)...)
	result, err := summarize(bytes.NewReader(data))
	require.NoError(t, err)
	require.EqualValues(t, 1, result.Packets)
	require.Zero(t, result.SupportedVersionCandidates)
}

package captureadapter

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOfflineProvenanceRoundTrip(t *testing.T) {
	info := capture.PacketInfo{Packet: gopacket.NewPacket(make([]byte, 60), layers.LinkTypeEthernet, gopacket.Default), LinkType: layers.LinkTypeEthernet, Interface: "source", SourcePath: "/capture", SourceIndex: 7, SourceSequence: 12, SourceInterfaceID: 3, Provenance: &offline.PacketProvenance{Derived: true, SourceIndex: 7, PhysicalOrdinal: 33, LogicalSequence: 12}}
	envelope := FromPacketInfo(info, pipeline.SourcePCAPReplay)
	result := ToPacketInfo(envelope)
	require.Equal(t, info.SourceIndex, result.SourceIndex)
	require.Equal(t, info.SourceSequence, result.SourceSequence)
	require.Equal(t, info.SourceInterfaceID, result.SourceInterfaceID)
	require.Equal(t, info.SourcePath, result.SourcePath)
	require.Same(t, info.Provenance, result.Provenance)
}

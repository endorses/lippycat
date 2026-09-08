package captureadapter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestRADIUSCaptureAdapterOwnsObservations(t *testing.T) {
	observation := &radius.Observation{Packet: []byte{1, 2, 3}, Direct: []radius.AttributionReference{{Criteria: []radius.CriterionReference{{Value: []byte("alice")}}}}}
	info := capture.PacketInfo{Packet: gopacket.NewPacket([]byte{1, 2, 3}, layers.LinkTypeEthernet, gopacket.Default), LinkType: layers.LinkTypeEthernet, Interface: "eth0", RADIUS: observation}
	envelope := FromPacketInfo(info)
	require.Equal(t, observation, envelope.RADIUS)
	observation.Direct[0].Criteria[0].Value[0] = 'b'
	require.Equal(t, "alice", string(envelope.RADIUS.Direct[0].Criteria[0].Value))
	restored := ToPacketInfo(envelope)
	envelope.RADIUS.Packet[0] = 9
	require.Equal(t, byte(1), restored.RADIUS.Packet[0])
	require.Equal(t, "eth0", restored.Interface)
}

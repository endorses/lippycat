package ebpfadmission

type PortRange struct{ Start, End uint16 }

type Options struct {
	SIPPorts          []uint16
	RTPPortRanges     []PortRange
	UDPOnly           bool
	EndpointCapacity  uint32
	SelectorCapacity  uint32
	Domains           uint32
	EvidenceBytes     uint32
	SIPPort           uint16
	ESPEnabled        bool
	ShadowSampleEvery uint32
}

package capture

import "github.com/google/gopacket"

// capturePolicyStamp is process-local provenance. It is never an on-wire claim
// or a policy authority; only the producer that minted the generation accepts it.
type capturePolicyStamp struct{ generation uint64 }

// StampCapturePolicy runs once at the producer's serialized capture boundary,
// before handing a packet to asynchronous analysis or buffering. Synthetic
// packets must explicitly copy the source generation after reassembly.
func StampCapturePolicy(packet gopacket.Packet, generation uint64) {
	if packet == nil || packet.Metadata() == nil {
		return
	}
	metadata := packet.Metadata()
	items := make([]interface{}, 0, len(metadata.AncillaryData)+1)
	for _, item := range metadata.AncillaryData {
		if _, stamp := item.(capturePolicyStamp); !stamp {
			items = append(items, item)
		}
	}
	items = append(items, capturePolicyStamp{generation: generation})
	metadata.AncillaryData = items
}

func CapturePolicyGeneration(packet gopacket.Packet) uint64 {
	if packet != nil && packet.Metadata() != nil {
		for _, item := range packet.Metadata().AncillaryData {
			if stamp, ok := item.(capturePolicyStamp); ok {
				return stamp.generation
			}
		}
	}
	return 0
}

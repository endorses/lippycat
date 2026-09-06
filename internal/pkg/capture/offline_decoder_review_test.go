package capture

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestOfflinePacketDecoderHeaderMutationParity(t *testing.T) {
	var decoder offlinePacketDecoder
	for _, ipv6 := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			raw := offlineDecoderFixture(t, ipv6, tcp, 40001, nil, []byte("payload with stable capture provenance"))
			for offset := 0; offset < len(raw)-38; offset++ {
				for _, value := range []byte{0, 1, 127, 255} {
					mutated := append([]byte(nil), raw...)
					mutated[offset] = value
					requireOfflinePacketParity(t, mutated, layers.LinkTypeEthernet, decoder.decode(mutated, layers.LinkTypeEthernet))
				}
			}
		}
	}
}

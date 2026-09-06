package capture

import (
	"encoding/binary"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"reflect"
)

// OfflinePacketDecoder decodes one packet at a time using bounded reusable layer
// storage. It is not safe for concurrent use. Packets, layers and decoded byte
// slices are borrowed until the next Decode; retained content must be copied.
// Unusual protocols use the standard gopacket decoder and its temporary storage.
type OfflinePacketDecoder = offlinePacketDecoder

func NewOfflinePacketDecoder() *OfflinePacketDecoder { return &offlinePacketDecoder{} }

// Decode borrows data without copying it. The caller must keep data unchanged
// until processing the returned packet is complete, before calling Decode again.
func (p *offlinePacketDecoder) Decode(data []byte, link layers.LinkType) gopacket.Packet {
	return p.decode(data, link)
}

// MemoryBytes reports the fixed decoder storage, including reusable TCP options
// and TLS record arrays. Callers separately account for borrowed input bytes and
// the standard decoder's temporary fallback allocations using their existing
// per-packet MaxRecordBytes scratch allowance; this value does not replace it.
func (*offlinePacketDecoder) MemoryBytes() uint64 {
	return uint64(reflect.TypeOf(offlinePacketDecoder{}).Size())
}

// offlinePacketDecoder owns one borrowed packet. Decode results and all their
// layers are valid only until the next decode. Only synchronous locator replay
// uses it; channels and packet observers continue receiving independent packets.
type offlinePacketDecoder struct {
	provenance        offline.PacketProvenance
	data              []byte
	metadata          gopacket.PacketMetadata
	ethernet          layers.Ethernet
	ipv4              layers.IPv4
	ipv6              layers.IPv6
	tcp               layers.TCP
	udp               layers.UDP
	tls               layers.TLS
	tlsChange         [8]layers.TLSChangeCipherSpecRecord
	tlsHandshake      [8]layers.TLSHandshakeRecord
	tlsAppData        [8]layers.TLSAppDataRecord
	tlsAlert          [8]layers.TLSAlertRecord
	options           [40]layers.TCPOption // At most forty one-byte options in a TCP header.
	decoded           [4]gopacket.Layer
	count             int
	network           gopacket.NetworkLayer
	transport         gopacket.TransportLayer
	application       gopacket.ApplicationLayer
	payload           gopacket.Payload
	errorLayer        gopacket.ErrorLayer
	applicationPacket gopacket.Packet
}

func (p *offlinePacketDecoder) decode(data []byte, link layers.LinkType) gopacket.Packet {
	// Reset every exposed field, including nil versus empty padding and stale
	// options, before using standard gopacket layer decoders again.
	*p = offlinePacketDecoder{data: data}
	if link == layers.LinkTypeEthernet && p.decodeCommon(data) {
		return p
	}
	return gopacket.NewPacket(data, link, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
}

func (p *offlinePacketDecoder) decodeCommon(data []byte) bool {
	if err := p.ethernet.DecodeFromBytes(data, p); err != nil {
		return false
	}
	p.decoded[0] = &p.ethernet
	var payload []byte
	var next gopacket.LayerType
	var applicationType gopacket.LayerType
	switch p.ethernet.EthernetType {
	case layers.EthernetTypeIPv4:
		if len(p.ethernet.Payload) < 20 || p.ethernet.Payload[0] != 0x45 {
			return false
		}
		if err := p.ipv4.DecodeFromBytes(p.ethernet.Payload, p); err != nil {
			return false
		}
		p.network, payload, next = &p.ipv4, p.ipv4.Payload, p.ipv4.NextLayerType()
	case layers.EthernetTypeIPv6:
		data := p.ethernet.Payload
		if len(data) < 40 || data[0]>>4 != 6 || (data[6] != byte(layers.IPProtocolTCP) && data[6] != byte(layers.IPProtocolUDP)) || (data[4] == 0 && data[5] == 0) {
			return false
		}
		if err := p.ipv6.DecodeFromBytes(data, p); err != nil {
			return false
		}
		p.network, payload, next = &p.ipv6, p.ipv6.Payload, p.ipv6.NextLayerType()
	default:
		return false
	}
	p.decoded[1] = p.network
	switch next {
	case layers.LayerTypeTCP:
		p.tcp.Options = p.options[:0]
		if err := p.tcp.DecodeFromBytes(payload, p); err != nil {
			return false
		}
		p.transport, payload = &p.tcp, p.tcp.Payload
		applicationType = p.tcp.NextLayerType()
	case layers.LayerTypeUDP:
		if err := p.udp.DecodeFromBytes(payload, p); err != nil || p.udp.Length == 0 {
			return false
		}
		p.transport, payload = &p.udp, p.udp.Payload
		applicationType = p.udp.NextLayerType()
	default:
		return false
	}
	if p.metadata.Truncated {
		return false
	}
	p.decoded[2], p.count = p.transport, 3
	if len(payload) > 0 {
		switch applicationType {
		case gopacket.LayerTypePayload:
			p.payload = gopacket.Payload(payload)
			p.application = &p.payload
		case layers.LayerTypeTLS:
			if !p.decodeTLS(payload) {
				// Decode invalid/partial TLS with gopacket itself so concrete
				// DecodeFailure layers, error text and truncation remain exact.
				// Ethernet/IP/TCP have already decoded successfully and need
				// not be allocated again. Retain only this callback's result.
				application := gopacket.NewPacket(payload, layers.LayerTypeTLS, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
				if len(application.Layers()) != 1 || application.ErrorLayer() == nil {
					return false // Unusual complete record collections retain full fallback.
				}
				if _, ok := application.ErrorLayer().(*gopacket.DecodeFailure); !ok {
					return false
				}
				p.applicationPacket = application
				p.errorLayer = application.ErrorLayer()
				p.metadata.Truncated = application.Metadata().Truncated
				p.decoded[3], p.count = p.errorLayer, 4
				return true
			}
			p.application = &p.tls
		default:
			return false
		}
		p.decoded[3], p.count = p.application, 4
	}
	return true
}

// decodeTLS bounds record storage before invoking the standard decoder. Unusual
// large record collections retain standard packet decode; incomplete records
// use standard application-only decode to preserve gopacket's failure layer.
func (p *offlinePacketDecoder) decodeTLS(payload []byte) bool {
	var counts [4]int
	for remaining := payload; len(remaining) > 0; {
		if len(remaining) < 5 || remaining[0] < 20 || remaining[0] > 23 {
			return false
		}
		kind := remaining[0] - 20
		counts[kind]++
		if counts[kind] > 8 {
			return false
		}
		length := 5 + int(binary.BigEndian.Uint16(remaining[3:5]))
		if length > len(remaining) {
			return false
		}
		remaining = remaining[length:]
	}
	// Leave absent record collections nil, matching a fresh layers.TLS.
	if counts[0] > 0 {
		p.tls.ChangeCipherSpec = p.tlsChange[:0]
	}
	if counts[1] > 0 {
		p.tls.Alert = p.tlsAlert[:0]
	}
	if counts[2] > 0 {
		p.tls.Handshake = p.tlsHandshake[:0]
	}
	if counts[3] > 0 {
		p.tls.AppData = p.tlsAppData[:0]
	}
	return p.tls.DecodeFromBytes(payload, p) == nil && !p.metadata.Truncated
}

func (p *offlinePacketDecoder) SetTruncated()                      { p.metadata.Truncated = true }
func (p *offlinePacketDecoder) Data() []byte                       { return p.data }
func (p *offlinePacketDecoder) Metadata() *gopacket.PacketMetadata { return &p.metadata }
func (p *offlinePacketDecoder) Layers() []gopacket.Layer           { return p.decoded[:p.count] }
func (p *offlinePacketDecoder) Layer(kind gopacket.LayerType) gopacket.Layer {
	for _, layer := range p.Layers() {
		if layer.LayerType() == kind {
			return layer
		}
	}
	return nil
}
func (p *offlinePacketDecoder) LayerClass(class gopacket.LayerClass) gopacket.Layer {
	for _, layer := range p.Layers() {
		if class.Contains(layer.LayerType()) {
			return layer
		}
	}
	return nil
}
func (p *offlinePacketDecoder) LinkLayer() gopacket.LinkLayer               { return &p.ethernet }
func (p *offlinePacketDecoder) NetworkLayer() gopacket.NetworkLayer         { return p.network }
func (p *offlinePacketDecoder) TransportLayer() gopacket.TransportLayer     { return p.transport }
func (p *offlinePacketDecoder) ApplicationLayer() gopacket.ApplicationLayer { return p.application }
func (p *offlinePacketDecoder) ErrorLayer() gopacket.ErrorLayer             { return p.errorLayer }

// Preserve gopacket's full formatting contract without putting formatting state
// or reflection on the indexing path.
func (p *offlinePacketDecoder) formatted() gopacket.Packet {
	packet := gopacket.NewPacket(p.data, layers.LinkTypeEthernet, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
	*packet.Metadata() = p.metadata
	return packet
}
func (p *offlinePacketDecoder) String() string { return p.formatted().String() }
func (p *offlinePacketDecoder) Dump() string   { return p.formatted().Dump() }

//go:build tui || all

package tui

import (
	"bytes"

	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
)

// decodeSMSBody consumes a complete framed SIP body. Decode errors are reflected
// by the result's bounded status; they do not suppress the original packet.
func decodeSMSBody(contentType string, body []byte) *sms.Message {
	if !sms.IsSMS(contentType) {
		return nil
	}
	message, err := sms.Decode(body)
	if err != nil && message == nil {
		return &sms.Message{Status: sms.StatusMalformed, Encoding: sms.EncodingUnknown}
	}
	return message
}

// enrichDisplaySMS is a compatibility fallback for complete raw SIP messages.
// It deliberately does not reconstruct streams or infer text from packet fragments.
func enrichDisplaySMS(packet *types.PacketDisplay) {
	enrichDisplaySMSFromPacket(packet, nil)
}

func enrichDisplaySMSFromPacket(packet *types.PacketDisplay, decoded gopacket.Packet) {
	metadata := packet.VoIPData
	if metadata == nil || metadata.SMS != nil || metadata.IsRTP {
		return
	}
	raw := metadata.RawSIP
	if len(raw) == 0 && (decoded != nil || len(packet.RawData) > 0) {
		if decoded == nil {
			decoded = gopacket.NewPacket(packet.RawData, packet.LinkType, gopacket.Default)
		}
		if transport := decoded.TransportLayer(); transport != nil {
			raw = transport.LayerPayload()
		}
	}
	if !bytes.Contains(raw, []byte("\r\n\r\n")) && !bytes.Contains(raw, []byte("\n\n")) {
		return
	}
	event, err := sip.Parse(raw, sip.ParseOptions{Timestamp: packet.Timestamp})
	if err != nil || event.CallID != metadata.CallID {
		return
	}
	// A TCP fragment without an explicit length cannot establish a complete body.
	if packet.Transport == 6 && event.Headers["content-length"] == "" {
		return
	}
	owned := *metadata
	owned.SMS = decodeSMSBody(event.ContentType, event.Body)
	owned.ContentType = event.ContentType
	owned.CSeqMethod, owned.CSeqNumber, owned.ViaBranch = event.CSeqMethod, event.CSeqNumber, event.ViaBranch
	packet.VoIPData = &owned
}

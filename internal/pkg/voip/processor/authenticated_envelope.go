package processor

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket/layers"
)

// EnvelopePolicy supplies a composition's authenticated source and parsed SIP
// selection checks. Forwarded metadata is never itself a selection verdict.
type EnvelopePolicy struct {
	ValidateSource func(pipeline.SourceProvenance) error
	Validate       func(sip.Event) error
	Match          func(sip.Event) (bool, []string, error)
}

// ProcessAuthenticatedEnvelope retains the original source kind and capture
// provenance while reusing the normal SIP orchestration and exact media registry.
// The caller must have authenticated a remote source, or explicitly established
// local capture provenance. Framed TCP messages use this same entry point after
// reassembly; it does not introduce a second TCP stream assembler.
func (p *Processor) ProcessAuthenticatedEnvelope(envelope *pipeline.PacketEnvelope, policy EnvelopePolicy) (*ProcessResult, error) {
	if envelope == nil || policy.ValidateSource == nil || policy.Match == nil {
		return nil, fmt.Errorf("authenticated envelope requires source validation and parsed selection")
	}
	if envelope.Source.Kind != pipeline.SourceGRPC && envelope.Source.Kind != pipeline.SourceLiveCapture {
		return nil, fmt.Errorf("unsupported authenticated envelope source")
	}
	if err := policy.ValidateSource(envelope.Source); err != nil {
		return nil, fmt.Errorf("validate envelope source: %w", err)
	}
	packet := envelope.Packet()
	if packet == nil {
		return nil, fmt.Errorf("authenticated envelope has no packet")
	}
	var payload []byte
	opts := sip.ParseOptions{Timestamp: envelope.CaptureTime}
	if network := packet.NetworkLayer(); network != nil {
		opts.SourceIP, opts.DestinationIP = network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
	}
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udp := layer.(*layers.UDP)
		if result := p.detectRTP(packet, udp); result != nil {
			return result, nil
		}
		payload = udp.Payload
		opts.SourcePort, opts.DestinationPort = uint16(udp.SrcPort), uint16(udp.DstPort)
	} else if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp := layer.(*layers.TCP)
		payload = tcp.Payload
		opts.SourcePort, opts.DestinationPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
	} else {
		return nil, nil
	}
	var selected bool
	var ids []string
	analysis := p.sipFlow.Analyze(sipflow.Message{
		Payload: payload, Envelope: envelope, ParseOptions: opts, FilterConfigured: true,
		Validate: func(event sip.Event) error {
			if err := validateCallID(event.CallID); err != nil {
				return err
			}
			if policy.Validate != nil {
				if err := policy.Validate(event); err != nil {
					return err
				}
			}
			var err error
			selected, ids, err = policy.Match(event)
			return err
		},
		Match: func(sip.Event) bool { return selected },
	})
	if analysis.Stage.Outcome == pipeline.OutcomeFiltered && analysis.SIP.CallID == "" {
		return nil, nil
	}
	if analysis.Stage.Err != nil {
		return nil, analysis.Stage.Err
	}
	if analysis.Stage.Outcome == pipeline.OutcomeFiltered {
		return &ProcessResult{PacketType: PacketTypeSIP, CallID: analysis.SIP.CallID, FilterEvaluated: true}, nil
	}
	if analysis.Stage.Outcome != pipeline.OutcomeAccepted {
		return nil, nil
	}
	attachment, ok := analysis.Attachment.(processorSIPAttachment)
	if !ok {
		return nil, fmt.Errorf("authenticated SIP observation has unexpected registry attachment")
	}
	return &ProcessResult{
		IsVoIP: true, PacketType: PacketTypeSIP, CallID: analysis.SIP.CallID, CallLifetime: attachment.lifetime,
		CallIDs: []string{analysis.SIP.CallID}, Metadata: attachment.pbMetadata, CallMetadata: attachment.metadata,
		FilterEvaluated: true, FilterMatched: selected, FilterIDs: append([]string(nil), ids...),
	}, analysis.MetadataError
}

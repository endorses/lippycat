//go:build hunter || all

package voip

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type hunterDiagnosticBackend struct{}

func (hunterDiagnosticBackend) PutEndpoint(context.Context, mediaadmission.EndpointKey) error {
	return nil
}
func (hunterDiagnosticBackend) DeleteEndpoint(context.Context, mediaadmission.EndpointKey) error {
	return nil
}
func (hunterDiagnosticBackend) ListEndpoints(context.Context, mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	return nil, nil
}
func (hunterDiagnosticBackend) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return nil
}

type hunterDiagnosticRecorder struct{ attributed, frames int }

func (*hunterDiagnosticRecorder) RecordSelection(mediaadmission.OwnerID, mediaadmission.DomainID, bool, bool, time.Time) {
}
func (d *hunterDiagnosticRecorder) RecordAttributedMedia(mediaadmission.OwnerID) { d.attributed++ }
func (*hunterDiagnosticRecorder) RecordFinalized(mediaadmission.OwnerID)         {}
func (d *hunterDiagnosticRecorder) RecordAttributedPacket(mediaadmission.OwnerID, mediaadmission.DomainID, []byte) {
	d.frames++
}

type hunterDiagnosticRaceFilter struct{ change func() }

func (*hunterDiagnosticRaceFilter) MatchPacket(gopacket.Packet) bool { return false }
func (f *hunterDiagnosticRaceFilter) MatchPacketLevelWithIDs(gopacket.Packet) (bool, []string) {
	f.change()
	return false, nil
}

func TestHunterAdmissionDiagnosticsRequireSelectedCurrentResolution(t *testing.T) {
	for _, scenario := range []string{"selected", "short RTCP", "wire truncated", "decoder truncated", "nonmedia", "unselected", "unresolved", "ambiguous", "reused after resolution"} {
		t.Run(scenario, func(t *testing.T) {
			tracker := TestCallTracker(t)
			registry := tracker.AdmissionRegistry()
			cfg := mediaadmission.DefaultConfig()
			cfg.Enabled = true
			controller, err := mediaadmission.NewController(t.Context(), cfg, hunterDiagnosticBackend{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
			metadata, err := mediaadmission.NewMetadataStore(cfg)
			require.NoError(t, err)
			diagnostics := &hunterDiagnosticRecorder{}
			bridge, err := sipadmission.New(sipadmission.Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: metadata, Diagnostics: diagnostics})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, bridge.Close()) })
			selected := pipeline.SIPResult{SDP: []byte("m=audio 0 RTP/AVP 0"), CallID: "selected-call", Method: "INVITE", FromTag: "from", ViaBranch: "branch", CSeqMethod: "INVITE", CSeqNumber: 1, Packet: &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "eth-test"}}}
			registry.Upsert(callregistry.Call{CallID: selected.CallID})
			if scenario != "unselected" {
				require.NoError(t, bridge.ObserveValidatedReceipt(&selected))
				require.NoError(t, bridge.Selected(selected))
			}
			if scenario != "unresolved" {
				registry.TryAssociateEndpoint(selected.CallID, "192.168.1.200:20000")
			}
			if scenario == "ambiguous" {
				registry.Upsert(callregistry.Call{CallID: "other-call"})
				registry.TryAssociateEndpoint("other-call", "192.168.1.200:20000")
			}
			buffers := NewBufferManager(time.Minute, 10)
			t.Cleanup(buffers.Close)
			handler := NewUDPPacketHandler(tracker, &recordingHunterForwarder{}, buffers)
			handler.admission = bridge
			t.Cleanup(handler.Close)
			if scenario == "reused after resolution" {
				handler.SetApplicationFilter(&hunterDiagnosticRaceFilter{change: func() {
					registry.Remove(selected.CallID, callregistry.EndCompleted)
					registry.Upsert(callregistry.Call{CallID: selected.CallID})
					replacement := selected
					replacement.FromTag, replacement.ViaBranch = "replacement-origin", "replacement-transaction"
					require.NoError(t, bridge.ObserveValidatedReceipt(&replacement))
					require.NoError(t, bridge.Selected(replacement))
				}})
			}
			payload := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
			if scenario == "short RTCP" {
				payload = []byte{0x80, 201, 0, 1, 0, 0, 0, 1}
			} else if scenario == "nonmedia" {
				payload[0] = 0 // STUN and DTLS must not clear missing-media diagnostics.
			}
			packet := createUDPPacket(30000, 20000, payload)
			packet.Metadata().CaptureLength, packet.Metadata().Length = len(packet.Data()), len(packet.Data())
			if scenario == "wire truncated" {
				packet.Metadata().Length += 8
			} else if scenario == "decoder truncated" {
				// Protocol decoding uncertainty is not a truncated original frame.
				packet.Metadata().Truncated = true
			}
			handler.handleRTPPacket(capture.PacketInfo{Packet: packet, Interface: "eth-test", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP))
			want := 0
			if scenario == "selected" || scenario == "short RTCP" || scenario == "wire truncated" || scenario == "decoder truncated" {
				want = 1
			}
			require.Equal(t, want, diagnostics.attributed)
			wantFrames := want
			if scenario == "wire truncated" {
				wantFrames = 0
			}
			require.Equal(t, wantFrames, diagnostics.frames, "exact correlation needs original full bytes independently of media attribution")
		})
	}
}

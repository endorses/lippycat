//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func wireFormatProcessor(t *testing.T, timestampFormat, targetFormat string) (*Processor, uuid.UUID, <-chan *x2x3.PDU) {
	t.Helper()
	cfg := storageKeyStartupConfig(t)
	cfg.ProcessorID, cfg.ListenAddr = "wire-format-processor", "localhost:0"
	cfg.LIDeliveryTimestampFormat = timestampFormat
	cfg.LIDeliveryMatchedTargetFormat = targetFormat
	cfg.LIRADIUSCorrelationLifetime = time.Minute
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	port, products := correlationMDF(t)
	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true, ProtocolType: "X2andX3"}))
	return p, did, products
}

func assertWireFormats(t *testing.T, pdu *x2x3.PDU, timestamp time.Time, timestampFormat, target string) {
	t.Helper()
	attribute := x2x3.FindAttribute(pdu.Attributes, x2x3.AttrTimestamp)
	require.NotNil(t, attribute)
	size := x2x3.LegacyTimestampSize
	if timestampFormat == "etsi-8" {
		size = x2x3.StandardTimestampSize
	}
	require.Len(t, attribute.Value, size)
	decoded, err := x2x3.NewAttributeParser().ParseTimestamp(attribute)
	require.NoError(t, err)
	require.True(t, timestamp.Equal(decoded), "capture time must survive the chosen representation exactly")
	matched := x2x3.FindAttribute(pdu.Attributes, x2x3.AttrMatchedTargetIdentifier)
	if target == "" {
		require.Nil(t, matched)
	} else {
		require.NotNil(t, matched)
		require.Equal(t, target, string(matched.Value))
	}
	for typ := x2x3.AttributeType(5); typ <= 16; typ++ {
		require.LessOrEqual(t, len(x2x3.FindAllAttributes(pdu.Attributes, typ)), 1, "non-repeatable attribute %d", typ)
	}
}

// Read actual TLS delivery after the production task/filter admission paths.
// The shared constructor must configure SIP, deferred RTP, and RADIUS equally.
func TestProcessorLIWireFormatCombinations(t *testing.T) {
	for _, timestampFormat := range []string{"legacy-12", "etsi-8"} {
		for _, targetFormat := range []string{"bare", "target-identifier"} {
			t.Run(timestampFormat+"/"+targetFormat, func(t *testing.T) {
				p, did, products := wireFormatProcessor(t, timestampFormat, targetFormat)
				xid := uuid.New()
				target := li.TargetIdentity{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.invalid"}
				require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{target}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3}))
				filter := "li-" + xid.String() + "-0"
				timestamp := time.Now().UTC().Truncate(time.Microsecond)
				packet := correlationIntegrationSIP(dirCallID, target.Value, timestamp)
				p.processLIPacketWithProvenance(packet, []string{filter}, nil)
				sipProduct := receiveProduct(t, products)
				expectedTarget := target.Value
				if targetFormat == "target-identifier" {
					expectedTarget = "<sipUri>sip:alice@example.invalid</sipUri>"
				}
				require.Equal(t, x2x3.PayloadFormatSIP, sipProduct.Header.PayloadFormat)
				require.Equal(t, packet.VoIPData.RawSIP, sipProduct.Payload)
				assertWireFormats(t, sipProduct, timestamp, timestampFormat, expectedTarget)

				rtp := orderedRTP(1, 42, "synthetic-hunter")
				rtp.Timestamp = timestamp.Add(time.Microsecond)
				p.processLIPacketWithProvenance(rtp, nil, []string{filter})
				rtpProduct := receiveProduct(t, products)
				require.Equal(t, x2x3.PDUTypeX3, rtpProduct.Header.Type)
				require.Equal(t, rtp.RawData, rtpProduct.Payload)
				require.Equal(t, sipProduct.Header.CorrelationID, rtpProduct.Header.CorrelationID)
				assertWireFormats(t, rtpProduct, rtp.Timestamp, timestampFormat, expectedTarget)

				radiusXID := uuid.New()
				require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: radiusXID, Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: "alice@example.test"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}))
				radiusTask, err := p.liManager.GetTaskDetails(radiusXID)
				require.NoError(t, err)
				batch, observations := radiusPOIBatch(t, p, radiusTask)
				p.processBatch(batch)
				var correlation uint64
				for index, observation := range observations {
					product := receiveProduct(t, products)
					require.Equal(t, x2x3.PayloadFormatRADIUS, product.Header.PayloadFormat)
					require.Equal(t, observation.Message.Raw, product.Payload)
					require.Equal(t, radiusXID, product.Header.XID)
					if index == 0 {
						correlation = product.Header.CorrelationID
					}
					require.Equal(t, correlation, product.Header.CorrelationID)
					expected := ""
					if targetFormat == "target-identifier" {
						expected = "<nai>alice@example.test</nai>"
					}
					assertWireFormats(t, product, observation.Capture.Timestamp, timestampFormat, expected)
					require.Equal(t, uint32(index), binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
				}
				// Neither field may be re-read from mutable configuration after
				// constructor validation has fixed the encoder's wire contract.
				p.config.LIDeliveryTimestampFormat = "invalid-after-start"
				p.config.LIDeliveryMatchedTargetFormat = "invalid-after-start"
				packet.Timestamp = timestamp.Add(2 * time.Microsecond)
				p.processLIPacketWithProvenance(packet, []string{filter}, nil)
				assertWireFormats(t, receiveProduct(t, products), packet.Timestamp, timestampFormat, expectedTarget)
			})
		}
	}
}

func TestProcessorLIMatchedTargetOmissionAndErrors(t *testing.T) {
	for _, format := range []string{"", "bare", "target-identifier"} {
		t.Run(fmt.Sprintf("format-%s", format), func(t *testing.T) {
			p, err := newTestProcessor(t, Config{ProcessorID: "target-format", ListenAddr: "localhost:0", LIEnabled: true, LIDeliveryMatchedTargetFormat: format})
			require.NoError(t, err)
			for _, test := range []struct {
				name    string
				targets []li.TargetIdentity
				want    string
				wantErr bool
			}{
				{"multiple", []li.TargetIdentity{{Type: li.TargetTypeSIPURI, Value: "sip:a@example.invalid"}, {Type: li.TargetTypeSIPURI, Value: "sip:b@example.invalid"}}, "", false},
				{"username", []li.TargetIdentity{{Type: li.TargetTypeUsername, Value: "legacy-user"}}, "legacy-user", false},
				{"invalid XML", []li.TargetIdentity{{Type: li.TargetTypeSIPURI, Value: "sip:a\x00@example.invalid"}}, "sip:a\x00@example.invalid", true},
			} {
				t.Run(test.name, func(t *testing.T) {
					product := x2x3.NewX2SIPPDU(uuid.New(), 42)
					err := p.addLIMatchedTarget(product, &li.InterceptTask{Targets: test.targets})
					if format == "target-identifier" && test.wantErr {
						require.Error(t, err)
						require.Nil(t, x2x3.FindAttribute(product.Attributes, x2x3.AttrMatchedTargetIdentifier))
						return
					}
					require.NoError(t, err)
					want := test.want
					if format == "target-identifier" && test.name == "username" {
						want = ""
					}
					attribute := x2x3.FindAttribute(product.Attributes, x2x3.AttrMatchedTargetIdentifier)
					if want == "" {
						require.Nil(t, attribute)
					} else {
						require.NotNil(t, attribute)
						require.Equal(t, want, string(attribute.Value))
					}
				})
			}
		})
	}
}

func TestProcessorLIWireFormatsRejectConfigurationBeforeOutputEffects(t *testing.T) {
	for _, field := range []string{"timestamp", "matched-target"} {
		t.Run(field, func(t *testing.T) {
			cfg := storageKeyStartupConfig(t)
			if field == "timestamp" {
				cfg.LIDeliveryTimestampFormat = "etsi-12"
			} else {
				cfg.LIDeliveryMatchedTargetFormat = "xml"
			}
			base := t.TempDir()
			cfg.WriteFile = filepath.Join(base, "unified.pcap")
			cfg.PcapWriterConfig = DefaultPcapWriterConfig()
			cfg.PcapWriterConfig.Enabled, cfg.PcapWriterConfig.OutputDir = true, filepath.Join(base, "per-call")
			cfg.AutoRotateConfig = DefaultAutoRotateConfig()
			cfg.AutoRotateConfig.Enabled, cfg.AutoRotateConfig.OutputDir = true, filepath.Join(base, "rotated")
			before := liDeliveryClient
			p, err := New(cfg)
			require.ErrorContains(t, err, "format")
			require.Nil(t, p)
			require.Same(t, before, liDeliveryClient, "failed constructor cannot publish another runtime")
			entries, err := os.ReadDir(base)
			require.NoError(t, err)
			require.Empty(t, entries)
			require.NoDirExists(t, cfg.LIDeliveryX2SpoolDir)
		})
	}
}

func TestProcessorLIStandardTimestampErrorsReachAccounting(t *testing.T) {
	p, did, _ := wireFormatProcessor(t, "etsi-8", "target-identifier")
	xid := uuid.New()
	target := li.TargetIdentity{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.invalid"}
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{target}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3}))
	filter := "li-" + xid.String() + "-0"
	before := p.getLIEncodingStats()
	packet := correlationIntegrationSIP(dirCallID, target.Value, time.Unix(-1, 0))
	p.processLIPacketWithProvenance(packet, []string{filter}, nil)
	rtp := orderedRTP(1, 42, "synthetic")
	rtp.Timestamp = time.Unix(1<<32, 0)
	p.processLIPacketWithProvenance(rtp, nil, []string{filter})
	after := p.getLIEncodingStats()
	require.Equal(t, before.X2Errors+1, after.X2Errors)
	require.Equal(t, before.X3Errors+1, after.X3Errors)
	require.Equal(t, before.X2Encoded, after.X2Encoded)
	require.Equal(t, before.X3Encoded, after.X3Encoded)
	require.Zero(t, liDeliveryClient.QueueDepth())

	radiusXID := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: radiusXID, Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: "alice@example.test"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}))
	task, err := p.liManager.GetTaskDetails(radiusXID)
	require.NoError(t, err)
	_, observations := radiusPOIBatch(t, p, task)
	observations[0].Capture.Timestamp = time.Unix(-1, 0)
	p.deliverLIRADIUS(task, observations[0])
	require.EqualValues(t, 1, p.radiusLIStats.EncodingErrors)
	require.Zero(t, p.radiusLIStats.Encoded)
	require.Zero(t, p.radiusLIStats.QueueAccepted)
	require.Equal(t, after.X2Errors+1, p.getLIEncodingStats().X2Errors)
}

// A schema-lexical target can expand beyond the existing 16-bit TLV bound.
// Exercise the production encoder/helper even though existing provisioning
// storage limits currently reject such a long task before the callback runs.
func TestProcessorLITypedTargetExpansionRespectsTLVBound(t *testing.T) {
	target := li.TargetIdentity{Type: li.TargetTypeSIPURI, Value: "sip:" + strings.Repeat("&", 14_000) + "@example.invalid"}
	encoded, err := li.MarshalTargetIdentifier(target)
	require.NoError(t, err)
	require.Less(t, len(target.Value), 65536)
	require.Greater(t, len(encoded), 65535)
	for _, format := range []string{"bare", "target-identifier"} {
		t.Run(format, func(t *testing.T) {
			p, err := newTestProcessor(t, Config{ProcessorID: "target-bound", ListenAddr: "localhost:0", LIEnabled: true, LIDeliveryTimestampFormat: "etsi-8", LIDeliveryMatchedTargetFormat: format})
			require.NoError(t, err)
			xid := uuid.New()
			packet := correlationIntegrationSIP("xml-expansion", "sip:alice@example.invalid", time.Now().UTC())
			product, err := p.liStorage.x2Encoder.EncodeIRI(packet, xid)
			require.NoError(t, err)
			require.NoError(t, p.addLIMatchedTarget(product, &li.InterceptTask{Targets: []li.TargetIdentity{target}}))
			data, err := product.MarshalBinary()
			attribute := x2x3.FindAttribute(product.Attributes, x2x3.AttrMatchedTargetIdentifier)
			require.NotNil(t, attribute)
			if format == "bare" {
				require.NoError(t, err)
				require.NotEmpty(t, data)
				require.Equal(t, target.Value, string(attribute.Value))
			} else {
				require.ErrorIs(t, err, x2x3.ErrTLVTooLarge)
				require.Nil(t, data, "failed typed encoding must not produce bytes for queue admission")
				require.Equal(t, encoded, string(attribute.Value), "an overflow must not substitute the bare representation")
			}
		})
	}
}

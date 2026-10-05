//go:build cli || all

package sniff

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func setSniffAnalysisConfig(t *testing.T, values map[string]any) {
	t.Helper()
	for key, value := range values {
		previous := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
}

func TestSniffConsumerlessAnalysisNeedsNoInputIdentity(t *testing.T) {
	setSniffAnalysisConfig(t, map[string]any{
		"logs.dir": "", "logs.streams": []string{}, "files.extract": false,
		"events.inventory.enabled": true, "events.drop_policy": "",
	})
	// Optional analysis must not even open the input to compute event identity.
	missing := filepath.Join(t.TempDir(), "missing.pcap")
	session, err := newSniffEventSession("", []string{missing}, "no-consumer", nil)
	require.NoError(t, err)
	require.Nil(t, session, "inventory policy alone does not demand analysis")
	for _, pipelineOwned := range []bool{false, true} {
		called := false
		withEventAnalysisMode([]string{missing}, "no-consumer", "", pipelineOwned, func(s *sniffEventSession) {
			called = true
			require.Nil(t, s)
		})
		require.True(t, called, "both optional observer and pipeline paths accept a nil session")
	}
}

func TestSniffConsumerlessAnalysisStillValidatesPolicy(t *testing.T) {
	setSniffAnalysisConfig(t, map[string]any{
		"logs.dir": "", "files.extract": false, "events.inventory.enabled": false,
		"logs.streams": []string{"known_hosts"},
	})
	session, err := newSniffEventSession("", nil, "invalid-policy", nil)
	require.ErrorContains(t, err, "requires enabled inventory")
	require.Nil(t, session)
}

func TestSniffExtractionWithoutLogsKeepsAnalysis(t *testing.T) {
	dir := t.TempDir()
	setSniffAnalysisConfig(t, map[string]any{
		"logs.dir": "", "logs.streams": []string{}, "files.extract": true,
		"files.extract_dir": dir, "events.queue_size": 32,
	})
	withEventAnalysisMode(nil, "extraction", "", true, func(session *sniffEventSession) {
		require.NotNil(t, session)
		payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
		packet := gopacket.NewPacket(tcpPacket(t, 80, 49152, payload), layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().Timestamp = time.Unix(10, 0)
		session.observe(&capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "fixture"})
	})
	paths, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, paths, 1, "requested extraction is a consumer even without event logs")
	content, err := os.ReadFile(filepath.Join(dir, paths[0].Name()))
	require.NoError(t, err)
	require.Equal(t, "hello", string(content))
}

func TestSniffOptionalObserverDemandAndRestoration(t *testing.T) {
	setSniffAnalysisConfig(t, map[string]any{
		"logs.dir": "", "logs.streams": []string{"dns"}, "logs.format": "json",
		"files.extract": false, "events.queue_size": 32, "logs.queue_size": 32,
	})
	input := filepath.Join(t.TempDir(), "dns.pcap")
	writeTestPCAP(t, input, dnsPacket(t))
	previousCalls := 0
	restore := capture.SetPacketObserver(func(*capture.PacketInfo) { previousCalls++ })
	defer restore()
	replay := func() {
		require.NoError(t, capture.StartOfflineSnifferOrdered([]string{input}, "", func(devices []pcaptypes.PcapInterface, filter string) {
			capture.RunOfflineOrdered(devices, filter, func(packets <-chan capture.PacketInfo) {
				for range packets {
				}
			})
		}))
	}
	withEventAnalysisMode([]string{input}, "observer-demand", "", false, func(session *sniffEventSession) {
		require.Nil(t, session)
		replay()
	})
	require.Equal(t, 1, previousCalls, "consumerless analysis does not replace the capture observer")
	dir := t.TempDir()
	viper.Set("logs.dir", dir)
	withEventAnalysisMode([]string{input}, "observer-demand", "", false, func(session *sniffEventSession) {
		require.NotNil(t, session)
		replay()
	})
	require.Equal(t, 1, previousCalls, "requested analysis owns the capture observer during capture")
	content, err := os.ReadFile(filepath.Join(dir, "dns.log"))
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(content)), "\n"), 1)
	replay()
	require.Equal(t, 2, previousCalls, "shutdown restores the observer after draining")
}

func TestProtocolSniffOrdinaryOutputIndependentOfLogs(t *testing.T) {
	setSniffAnalysisConfig(t, map[string]any{
		"logs.dir": "", "logs.streams": []string{"dns"}, "logs.format": "json",
		"files.extract": false, "sniff.quiet": false, "sniff.format": "json",
		"events.queue_size": 32, "logs.queue_size": 32,
	})
	originalFilter, originalReadFile := filter, readFile
	t.Cleanup(func() { filter, readFile = originalFilter, originalReadFile })
	filter, readFile = "", ""
	input := filepath.Join(t.TempDir(), "dns.pcap")
	writeTestPCAP(t, input, dnsPacket(t))
	var output [2][]byte
	for mode := range output {
		var dir string
		if mode == 1 {
			dir = t.TempDir()
		}
		viper.Set("logs.dir", dir)
		path := filepath.Join(t.TempDir(), "stdout.jsonl")
		f, err := os.Create(path)
		require.NoError(t, err)
		func() {
			previous := os.Stdout
			os.Stdout = f
			defer func() { os.Stdout = previous }()
			dnsHandler(dnsCmd, []string{input})
		}()
		require.NoError(t, f.Close())
		output[mode], err = os.ReadFile(path)
		require.NoError(t, err)
		if mode == 1 {
			content, err := os.ReadFile(filepath.Join(dir, "dns.log"))
			require.NoError(t, err)
			require.Len(t, strings.Split(strings.TrimSpace(string(content)), "\n"), 1)
		}
	}
	require.Contains(t, string(output[0]), "example.test")
	var display [2]types.PacketDisplay
	var statistics [2][]byte
	for i := range output {
		packet, rest, found := bytes.Cut(output[i], []byte("\n"))
		require.True(t, found)
		require.NoError(t, json.Unmarshal(packet, &display[i]))
		statistics[i] = rest
	}
	// Entropy sums use map iteration, so independent runs can differ by a few
	// floating-point rounding bits. All other packet fields and statistics match.
	require.InDelta(t, display[0].DNSData.EntropyScore, display[1].DNSData.EntropyScore, 1e-14)
	display[1].DNSData.EntropyScore = display[0].DNSData.EntropyScore
	require.Equal(t, display[0], display[1])
	require.Equal(t, statistics[0], statistics[1])
}

func TestSniffLocalRADIUSOutputIndependentOfAnalysis(t *testing.T) {
	for _, dedicated := range []bool{false, true} {
		for _, kind := range []pipeline.SourceKind{pipeline.SourceLiveCapture, pipeline.SourcePCAPReplay} {
			t.Run(map[pipeline.SourceKind]string{pipeline.SourceLiveCapture: "live", pipeline.SourcePCAPReplay: "offline"}[kind]+map[bool]string{false: "/generic", true: "/dedicated"}[dedicated], func(t *testing.T) {
				setSniffAnalysisConfig(t, map[string]any{
					"logs.dir": "", "logs.streams": []string{"radius"}, "logs.format": "json",
					"files.extract": false, "events.queue_size": 128, "logs.queue_size": 128,
				})
				input := filepath.Join(radiusfixture.Write(t), "acceptance.pcap")
				var config *radiusconfig.Config
				if dedicated {
					cmd := &cobra.Command{}
					radiusconfig.RegisterFlags(cmd)
					v := viper.New()
					v.Set("radius.username", "alice@example.test")
					v.Set("radius.ports", "1812,1813,19120")
					cfg, err := radiusconfig.Resolve(cmd, v)
					require.NoError(t, err)
					config = &cfg
				}
				var outputs [3][]types.PacketDisplay
				var observations [3]map[string]*radius.Observation
				for mode := 0; mode < 3; mode++ {
					var sink events.Sink
					var dir string
					if mode == 1 {
						dir = t.TempDir()
					} else if mode == 2 {
						sink = &sniffEventSink{}
					}
					var files []string
					if kind == pipeline.SourcePCAPReplay {
						files = []string{input}
					}
					session, err := newSniffEventSession(dir, files, "radius-demand", sink)
					require.NoError(t, err)
					if mode == 0 {
						require.Nil(t, session)
					}
					observations[mode] = map[string]*radius.Observation{}
					var out bytes.Buffer
					fanout, err := pipeline.NewPacketFanout(
						pipeline.SinkRegistration{Name: "cli", Sink: newCLIEnvelopeSink(&out, "json", false)},
						pipeline.SinkRegistration{Name: "observations", Sink: &radiusObservationSink{observations: observations[mode]}},
					)
					require.NoError(t, err)
					local := &localEnvelopePipeline{fanout: fanout, radiusConfig: config, logSession: session}
					local.process(readRADIUSPackets(t, input), kind)
					local.close()
					outputs[mode] = comparablePacketOutput(t, out.Bytes())
					if session != nil {
						session.analysis.EOF()
						session.analysis.Close()
						require.NoError(t, session.dispatcher.Close(context.Background()))
					}
					if mode == 2 {
						eventSink := sink.(*sniffEventSink)
						counts := map[string]int{}
						for _, event := range eventSink.events {
							if radiusEvent, ok := event.(events.RADIUSEvent); ok {
								counts[radiusEvent.ObservationID]++
							}
						}
						require.Len(t, counts, len(observations[mode]))
						for id := range observations[mode] {
							require.Equal(t, 1, counts[id], "one analysis event per packet observation")
						}
					}
				}
				require.NotEmpty(t, observations[0])
				require.Equal(t, outputs[0], outputs[1], "logs do not change ordinary output")
				require.Equal(t, outputs[0], outputs[2], "explicit sink does not change ordinary output")
				associated := 0
				for _, observation := range observations[0] {
					if dedicated {
						require.True(t, radiusconfig.Selected(config.Matcher, observation))
					}
					if observation.Association.Status == radius.AssociationUnique {
						associated++
					}
				}
				require.Positive(t, associated, "nil analysis session preserves response association")
			})
		}
	}
}

func comparablePacketOutput(t *testing.T, data []byte) []types.PacketDisplay {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	var output []types.PacketDisplay
	for {
		var display types.PacketDisplay
		if err := d.Decode(&display); err == io.EOF {
			return output
		} else {
			require.NoError(t, err)
		}
		if display.RADIUSData != nil {
			// Independent runs deliberately use fresh capture epochs. Compare
			// sequences and response linkage while ignoring only that random prefix.
			_, display.RADIUSData.ObservationID, _ = strings.Cut(display.RADIUSData.ObservationID, ":")
			_, display.RADIUSData.RequestID, _ = strings.Cut(display.RADIUSData.RequestID, ":")
		}
		output = append(output, display)
	}
}

func readRADIUSPackets(t *testing.T, input string) <-chan capture.PacketInfo {
	t.Helper()
	f, err := os.Open(input)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	packets := make(chan capture.PacketInfo, 128)
	for {
		raw, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		packets <- capture.PacketInfo{Packet: packet, LinkType: r.LinkType(), Interface: "fixture", SourcePath: input}
	}
	close(packets)
	return packets
}

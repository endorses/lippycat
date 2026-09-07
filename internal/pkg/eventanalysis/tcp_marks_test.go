package eventanalysis

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/reassembly"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

type markScatterGather struct {
	reassembly.ScatterGather
	infos []gopacket.CaptureInfo
}

func (sg markScatterGather) Lengths() (int, int) { return len(sg.infos), 0 }
func (sg markScatterGather) CaptureInfo(offset int) gopacket.CaptureInfo {
	return sg.infos[offset]
}

func TestAppendMarksPreservesIntermediateCaptureContexts(t *testing.T) {
	a := gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), AncillaryData: []interface{}{
		reassemblyContext{source: Source{InputFile: "test.pcap"}, scope: events.CaptureScopeFull},
	}}
	b := gopacket.CaptureInfo{Timestamp: a.Timestamp, AncillaryData: []interface{}{
		reassemblyContext{source: Source{InputFile: "test.pcap"}, scope: events.CaptureScopeFiltered, partial: true},
	}}
	s := &applicationStream{buffer: []byte("prefix")}
	s.appendMarks(markScatterGather{infos: []gopacket.CaptureInfo{a, a, b, b, a}})
	require.Len(t, s.marks, 3)
	require.Equal(t, []int{8, 10, 11}, []int{s.marks[0].end, s.marks[1].end, s.marks[2].end})
	mark := s.contextThrough(11)
	require.Equal(t, a.Timestamp, mark.ci.Timestamp)
	require.Equal(t, events.CaptureScopeFiltered, mark.ctx.scope)
	require.True(t, mark.ctx.partial)

	// Missing metadata marks the stream partial; the following range still
	// merges with the preceding equal context and uses the full byte offset.
	s.buffer = make([]byte, 11)
	s.appendMarks(markScatterGather{infos: []gopacket.CaptureInfo{{}, a, a}})
	require.True(t, s.partial)
	require.Len(t, s.marks, 3)
	require.Equal(t, 14, s.marks[2].end)
}

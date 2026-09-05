package reassembly

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

func TestMultiPageCaptureInfoPreservesPacketContext(t *testing.T) {
	pc := newPageCache()
	ci := gopacket.CaptureInfo{
		Timestamp: time.Unix(123, 456), CaptureLength: 4096, Length: 4096,
		InterfaceIndex: 7, AncillaryData: []interface{}{"original queued packet"},
	}
	ctx := assemblerSimpleContext(ci)
	payload := bytes.Repeat([]byte("x"), 2*pageBytes+37)
	lp := livePacket{bytes: payload, seq: 100, ac: &ctx}
	first, last, count := lp.convertToPages(pc, 0, &ctx)
	require.Equal(t, 3, count)
	var all []byteContainer
	for p := first; p != nil; p = p.next {
		all = append(all, p)
	}
	sg := reassemblyObject{all: all}
	require.Equal(t, payload, sg.Fetch(len(payload)))
	for _, offset := range []int{0, pageBytes - 1, pageBytes, 2*pageBytes - 1, 2 * pageBytes, len(payload) - 1} {
		require.Equal(t, ci, sg.CaptureInfo(offset), "offset %d", offset)
	}
	require.Equal(t, 3, sg.Stats().Chunks)
	require.Equal(t, 1, sg.Stats().Packets, "continuation pages must not count as extra packets")

	// Retain only a suffix beginning inside a continuation page. The first
	// page is returned to the cache, so metadata must survive independently.
	sg.KeepFrom(pageBytes + 23)
	a := Assembler{pc: pc, cacheSG: sg}
	half := halfconnection{first: first, last: last, pages: count}
	otherContext := assemblerSimpleContext(gopacket.CaptureInfo{InterfaceIndex: 99})
	a.cleanSG(&half, &otherContext)
	require.Nil(t, first.ac, "released page must not retain packet context")
	require.Nil(t, first.continuationContext)
	require.NotNil(t, half.saved)
	require.Same(t, &ctx, half.saved.assemblerContext(), "flush must use retained packet context")

	var retained []byteContainer
	for p := half.saved; p != nil; p = p.next {
		retained = append(retained, p)
	}
	saved := reassemblyObject{all: retained}
	want := payload[pageBytes+23:]
	require.Equal(t, want, saved.Fetch(len(want)))
	require.Equal(t, ci, saved.CaptureInfo(0))
	require.Equal(t, ci, saved.CaptureInfo(len(want)-1))
	require.Equal(t, 0, saved.Stats().Packets, "retaining a continuation must not introduce a packet boundary")
	for _, r := range retained {
		p := r.(*page)
		p.release(pc)
		require.Nil(t, p.ac)
		require.Nil(t, p.continuationContext, "cached pages must release ancillary context references")
		require.Nil(t, p.prev)
		require.Nil(t, p.next)
	}
	require.Zero(t, pc.used)
}

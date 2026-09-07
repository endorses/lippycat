package reassembly

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

// Embedding only the public interface hides the local span implementation.
type legacyScatterGather struct{ ScatterGather }

func TestForEachCaptureInfo(t *testing.T) {
	pc := newPageCache()
	ctx := assemblerSimpleContext(gopacket.CaptureInfo{InterfaceIndex: 1})
	lp := livePacket{bytes: bytes.Repeat([]byte("a"), 2*pageBytes+37), ac: &ctx}
	first, _, _ := lp.convertToPages(pc, 0, &ctx)
	all := []byteContainer{&livePacket{}} // Empty containers need no context.
	for p := first; p != nil; p = p.next {
		all = append(all, p)
	}
	all = append(all,
		&livePacket{bytes: []byte("bb"), ac: testCustomContext(2)},
		&livePacket{},
		&livePacket{bytes: []byte("aaa"), ac: &ctx},
	)
	sg := &reassemblyObject{all: all}
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			var input ScatterGather = sg
			if legacy {
				input = legacyScatterGather{sg}
			}
			start, visits := 0, 0
			ForEachCaptureInfo(input, func(end int, ci gopacket.CaptureInfo) {
				require.Greater(t, end, start)
				for offset := start; offset < end; offset++ {
					require.Equal(t, sg.CaptureInfo(offset), ci)
				}
				start = end
				visits++
			})
			available, _ := sg.Lengths()
			require.Equal(t, available, start)
			if legacy {
				require.Equal(t, available, visits)
			} else {
				require.Equal(t, 5, visits)
			}
		})
	}
	for p := first; p != nil; {
		next := p.next
		p.release(pc)
		p = next
	}
}

func TestForEachCaptureInfoEmpty(t *testing.T) {
	ForEachCaptureInfo(&reassemblyObject{}, func(int, gopacket.CaptureInfo) {
		t.Fatal("empty scatter gather must not invoke callback")
	})
}

func BenchmarkForEachCaptureInfo(b *testing.B) {
	for _, size := range []int{1500, 64 * 1024} {
		for _, legacy := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/legacy=%t", size, legacy), func(b *testing.B) {
				pc := newPageCache()
				ctx := assemblerSimpleContext(gopacket.CaptureInfo{InterfaceIndex: 1})
				lp := livePacket{bytes: make([]byte, size), ac: &ctx}
				first, _, _ := lp.convertToPages(pc, 0, &ctx)
				var all []byteContainer
				for p := first; p != nil; p = p.next {
					all = append(all, p)
				}
				var sg ScatterGather = &reassemblyObject{all: all}
				if legacy {
					sg = legacyScatterGather{sg}
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					ForEachCaptureInfo(sg, func(_ int, ci gopacket.CaptureInfo) {
						if ci.InterfaceIndex != 1 {
							b.Fatal("capture context lost")
						}
					})
				}
			})
		}
	}
}

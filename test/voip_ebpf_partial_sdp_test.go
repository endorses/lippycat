//go:build linux && all

package test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This runs real tap/hunter/processor composition with eBPF disabled. It shares
// the isolated live-traffic harness because command output, not parser success,
// is the evidence needed for restoring independent valid media sections.
func TestVoIPEBPFCommandPartialSDPDisabledAdmission(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		t.Run(topology, func(t *testing.T) {
			f := newAdmissionCommandFixture(t, binary, topology, "broad", "{}\n", "--rtp-port-range", "10000-13999")
			signal := func(id, user string, port uint16) []byte {
				body := fmt.Sprintf("v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio %d RTP/AVP 0\r\nm=audio invalid RTP/AVP 0\r\nm=video %d RTP/AVP 96\r\n", port, port+1000)
				head := strings.SplitN(string(admissionSIP(id, user, port)), "Content-Length:", 2)[0]
				return []byte(fmt.Sprintf("%sContent-Length: %d\r\n\r\n%s", head, len(body), body))
			}
			require.Eventually(t, func() bool {
				require.NoError(t, f.sender(5060, 5060, signal("partial-selected-call", "selected", 10000)))
				return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("partial-selected-call"))
			}, 20*time.Second, 100*time.Millisecond, "selected signaling reaches ordinary per-call output")
			require.NoError(t, f.sender(5060, 5060, signal("partial-unselected-call", "other", 12000)))
			media := func(marker string) []byte {
				return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(marker)...)
			}
			require.Eventually(t, func() bool {
				require.NoError(t, f.sender(7000, 10000, media("PARTIAL-VALID-BEFORE")))
				require.NoError(t, f.sender(7000, 11000, media("PARTIAL-VALID-AFTER")))
				captured := readAdmissionPCAPs(t, f.out)
				return bytes.Contains(captured, []byte("PARTIAL-VALID-BEFORE")) && bytes.Contains(captured, []byte("PARTIAL-VALID-AFTER"))
			}, 20*time.Second, 100*time.Millisecond, "valid sections before and after invalid media reach selected output with eBPF disabled")
			require.NoError(t, f.sender(7000, 12000, media("PARTIAL-UNSELECTED")))
			require.NoError(t, f.sender(7000, 14000, media("PARTIAL-EXCLUDED-PORT")))
			f.stop()
			captured := readAdmissionPCAPs(t, f.out)
			require.NotContains(t, string(captured), "PARTIAL-UNSELECTED")
			require.NotContains(t, string(captured), "PARTIAL-EXCLUDED-PORT")
		})
	}
}

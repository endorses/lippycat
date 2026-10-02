//go:build linux && all

package test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestVoIPEBPFCommandDomains(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		t.Run(topology, func(t *testing.T) {
			// Interfaces 0 and 1 see one domain; interface 2 sees overlapping addresses
			// and Call-IDs in a separate domain. All sockets share the session maps.
			f := newAdmissionCommandFixtureDomains(t, binary, topology, "enforce", "{}\n", []uint32{0, 0, 1})
			scope := func(domain uint32) *management.MediaAdmissionScope {
				for _, h := range f.status().GetHunters() {
					for _, s := range h.GetStats().GetRtpEbpf().GetScopes() {
						if s.Domain == domain {
							return s
						}
					}
				}
				return nil
			}
			require.Eventually(t, func() bool {
				require.NoError(t, f.senders[0](5060, 5060, admissionSIP("overlapping-call", "selected", 42002)))
				require.NoError(t, f.senders[2](5060, 5060, admissionSIP("overlapping-call", "unrelated", 42002)))
				shared, isolated := scope(0), scope(1)
				return shared != nil && isolated != nil && shared.InstalledEndpoints == 2 && isolated.InstalledEndpoints == 0
			}, 20*time.Second, 100*time.Millisecond, "selection cannot leak into an overlapping domain")
			before0, before1 := scope(0), scope(1)
			payload := func(s string) []byte { return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(s)...) }
			require.NoError(t, f.senders[1](42000, 42002, payload("DOMAIN-SHARED-MEDIA")))
			require.NoError(t, f.senders[2](42000, 42002, payload("DOMAIN-ISOLATED-MEDIA")))
			require.Eventually(t, func() bool {
				a, b := scope(0), scope(1)
				return a != nil && b != nil && a.DecisionCounters[1] > before0.DecisionCounters[1] && b.DecisionCounters[0] > before1.DecisionCounters[0]
			}, 20*time.Second, 100*time.Millisecond, "cross-interface admission only inside the shared domain")
			require.Eventually(t, func() bool { return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("DOMAIN-SHARED-MEDIA")) }, 15*time.Second, 100*time.Millisecond, "userspace shares authoritative ownership inside one domain")
			f.stop()
			require.NotContains(t, string(readAdmissionPCAPs(t, f.out)), "DOMAIN-ISOLATED-MEDIA")
		})
	}
}

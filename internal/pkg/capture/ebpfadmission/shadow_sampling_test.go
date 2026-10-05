//go:build linux

package ebpfadmission

import (
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestKernelShadowSamplingParity(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("requires explicit isolated privileged kernel execution")
	}
	for _, every := range []uint32{1, 7} {
		backend, err := NewBackend(Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 2, EvidenceBytes: 4096, ShadowSampleEvery: every})
		require.NoError(t, err)
		reader, err := backend.DecisionReader()
		require.NoError(t, err)
		for _, domain := range []mediaadmission.DomainID{0, 1} {
			require.NoError(t, backend.SetControl(t.Context(), domain, mediaadmission.Control{Mode: mediaadmission.KernelShadow, Generation: 3}))
			program, err := backend.NewProgram(domain, 65535, 1, nil)
			require.NoError(t, err)
			for _, length := range []int{1, 13, 14, 255, 256, 257} {
				for variant := 0; variant < 12; variant++ {
					frame := make([]byte, length)
					for i := range frame {
						frame[i] = byte(i + variant)
					}
					bounded := frame
					if len(bounded) > mediaadmission.ShadowIdentityBytes {
						bounded = bounded[:mediaadmission.ShadowIdentityBytes]
					}
					want := mediaadmission.ShadowSamplingHash(domain, uint32(length), bounded)%every == 0
					// Every duplicate must have the same eligibility and each
					// eligible copy must emit its own decision record.
					for duplicate := 0; duplicate < 2; duplicate++ {
						ret, _, err := program.Test(testRunFrame(frame))
						require.NoError(t, err)
						require.Equal(t, uint32(65535), ret)
						reader.SetDeadline(time.Now().Add(5 * time.Millisecond))
						record, err := reader.Read()
						if !want {
							require.ErrorIs(t, err, os.ErrDeadlineExceeded, "unsampled frame domain=%d len=%d variant=%d", domain, length, variant)
							continue
						}
						require.NoError(t, err, "eligible frame domain=%d len=%d variant=%d", domain, length, variant)
						event, err := DecodeDecision(record.RawSample)
						require.NoError(t, err)
						require.Equal(t, domain, event.Domain)
						require.Equal(t, every, event.SampleEvery)
						require.Equal(t, uint32(length), event.Length)
						if length <= mediaadmission.ShadowIdentityBytes {
							require.Equal(t, uint32(length), event.IdentityLength)
							require.Equal(t, frame, event.Identity[:length])
							require.True(t, mediaadmission.ShadowFrameEligible(domain, frame, every))
						} else {
							require.Zero(t, event.IdentityLength, "sampled prefix cannot establish full identity")
						}
					}
				}
			}
			require.NoError(t, program.Close())
		}
		require.NoError(t, reader.Close())
		require.NoError(t, backend.Close())
	}
}

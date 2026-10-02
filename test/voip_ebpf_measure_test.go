//go:build linux && all

package test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type admissionMeasurement struct {
	Mode                                                               string `json:"mode"`
	MatchPercent, Legs, Calls                                          int
	LifetimeMS, OfferedCallsPerSecond, ActualCallsPerSecond            float64
	WorkloadSeconds, ProcessCPUSeconds                                 float64
	MaxRSSBytes, AllocatedBytes, Allocations                           uint64
	SentMedia, SentSelectedInitial, OutputMedia, OutputSelectedInitial uint64
	Captured, Forwarded, CaptureLosses, QueueLosses                    uint64
	PeakQueuePackets, PeakEndpoints, UpdateErrors, CompatibilityPasses uint64
	SDPCaptureToPublicationUpperNS                                     int64
	PublicationSampleAvailable                                         bool
	DecisionCounters                                                   []uint64
}

// TestVoIPEBPFMeasurement is an opt-in exploratory workload, without performance
// assertions. All modes run the same 100-call/s schedule and write selected calls.
func TestVoIPEBPFMeasurement(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_MEASURE") != "1" {
		t.Skip("not exercised: LIPPYCAT_EBPF_MEASURE=1 make test-ebpf")
	}
	require.Equal(t, "1", os.Getenv("LIPPYCAT_EBPF_TEST"), "measurement requires isolated privileged runner")
	binaryPath := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binaryPath)
	for _, scenario := range []struct {
		match, legs int
		lifetime    time.Duration
	}{{10, 1, time.Second}, {50, 2, 2 * time.Second}} {
		for _, mode := range []string{"broad", "shadow", "enforce"} {
			t.Run(fmt.Sprintf("%s/match%d/legs%d", mode, scenario.match, scenario.legs), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				debugAddress := listener.Addr().String()
				require.NoError(t, listener.Close())
				f := newAdmissionCommandFixture(t, binaryPath, "tap", mode, "{}\n", "--debug-listen", debugAddress)
				probeID := "publication-probe"
				var published int64
				require.NoError(t, f.sender(5060, 5060, admissionSIP(probeID, "selected", 19002)))
				if mode != "broad" {
					require.Eventually(t, func() bool {
						s := f.snapshot()
						if s != nil && s.InstalledEndpoints == 2 {
							published = s.LastPublishedUnixNs
							return true
						}
						return false
					}, 20*time.Second, 10*time.Millisecond)
				}
				allocatedBefore, mallocBefore := admissionHeapCounters(t, debugAddress)
				result := admissionMeasurement{Mode: mode, MatchPercent: scenario.match, Legs: scenario.legs, Calls: 200, LifetimeMS: float64(scenario.lifetime / time.Millisecond), OfferedCallsPerSecond: 100}
				type mediaLeg struct {
					id            string
					port          uint16
					selected      bool
					expires, next time.Time
					sequence      uint16
				}
				var active []mediaLeg
				started := time.Now()
				lastCall := started
				calls := 0
				sampleAt := started
				sample := func() {
					status := f.status()
					if status == nil {
						return
					}
					for _, h := range status.Hunters {
						st := h.GetStats()
						if st == nil {
							continue
						}
						result.Captured = st.PacketsCaptured
						result.Forwarded = st.PacketsForwarded
						result.CaptureLosses = st.CaptureLosses
						result.QueueLosses = st.QueueLosses
						q := st.CaptureBufferRegularLen + st.CaptureBufferSipLen + st.CaptureBufferOutputLen
						if q > result.PeakQueuePackets {
							result.PeakQueuePackets = q
						}
						for _, s := range st.GetRtpEbpf().GetScopes() {
							if s.InstalledEndpoints > result.PeakEndpoints {
								result.PeakEndpoints = s.InstalledEndpoints
							}
							result.UpdateErrors = s.UpdateErrors
							result.DecisionCounters = append([]uint64(nil), s.DecisionCounters...)
							if len(s.DecisionCounters) == 16 {
								result.CompatibilityPasses = s.DecisionCounters[5] + s.DecisionCounters[6] + s.DecisionCounters[7] + s.DecisionCounters[8]
							}
						}
					}
				}
				sendMedia := func(leg *mediaLeg, initial bool) {
					marker := "WORKLOAD-unselected"
					if leg.selected {
						marker = "WORKLOAD-selected"
					}
					if initial {
						marker += "-initial"
						if leg.selected {
							result.SentSelectedInitial++
						}
					}
					payload := append(make([]byte, 12), []byte(marker)...)
					payload[0] = 0x80
					binary.BigEndian.PutUint16(payload[2:4], leg.sequence)
					binary.BigEndian.PutUint32(payload[4:8], uint32(leg.sequence)*160)
					binary.BigEndian.PutUint32(payload[8:12], uint32(leg.port))
					require.NoError(t, f.sender(leg.port-2, leg.port, payload))
					result.SentMedia++
					leg.sequence++
				}
				for calls < result.Calls || len(active) > 0 {
					now := time.Now()
					for calls < result.Calls && !now.Before(started.Add(time.Duration(calls)*10*time.Millisecond)) {
						for n := 0; n < scenario.legs; n++ {
							selected := calls%100 < scenario.match
							user := "unrelated"
							if selected {
								user = "selected"
							}
							leg := mediaLeg{id: fmt.Sprintf("workload-%d-leg-%d", calls, n), port: uint16(20000 + (calls*scenario.legs+n)*4), selected: selected, expires: now.Add(scenario.lifetime), next: now.Add(20 * time.Millisecond)}
							require.NoError(t, f.sender(5060, 5060, admissionSIP(leg.id, user, leg.port)))
							sendMedia(&leg, true)
							active = append(active, leg)
						}
						calls++
						lastCall = now
					}
					retained := active[:0]
					for i := range active {
						leg := active[i]
						if !now.Before(leg.expires) {
							terminal := []byte(fmt.Sprintf("SIP/2.0 200 OK\r\nFrom: <sip:receiver@example.test>;tag=destination\r\nTo: <sip:%s@example.test>;tag=origin\r\nCall-ID: %s\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n", map[bool]string{true: "selected", false: "unrelated"}[leg.selected], leg.id))
							require.NoError(t, f.sender(5060, 5060, terminal))
							continue
						}
						if !now.Before(leg.next) {
							sendMedia(&leg, false)
							leg.next = leg.next.Add(20 * time.Millisecond)
						}
						retained = append(retained, leg)
					}
					active = retained
					if !now.Before(sampleAt) {
						sample()
						sampleAt = now.Add(100 * time.Millisecond)
					}
					time.Sleep(time.Millisecond)
				}
				result.WorkloadSeconds = time.Since(started).Seconds()
				result.ActualCallsPerSecond = float64(result.Calls-1) / lastCall.Sub(started).Seconds()
				sample()
				allocatedAfter, mallocAfter := admissionHeapCounters(t, debugAddress)
				result.AllocatedBytes = allocatedAfter - allocatedBefore
				result.Allocations = mallocAfter - mallocBefore
				f.stop()
				processState := *f.processState
				require.NotNil(t, processState)
				result.ProcessCPUSeconds = (processState.UserTime() + processState.SystemTime()).Seconds()
				usage, ok := processState.SysUsage().(*syscall.Rusage)
				require.True(t, ok)
				result.MaxRSSBytes = uint64(usage.Maxrss) * 1024
				admissionReadPackets(t, f.out, func(data []byte, at time.Time) {
					if bytes.Contains(data, []byte("WORKLOAD-selected")) {
						result.OutputMedia++
					}
					if bytes.Contains(data, []byte("WORKLOAD-selected-initial")) {
						result.OutputSelectedInitial++
					}
					require.NotContains(t, string(data), "WORKLOAD-unselected", "admission must preserve userspace output filtering")
					if published != 0 && bytes.Contains(data, []byte("Call-ID: "+probeID+"\r\n")) {
						result.PublicationSampleAvailable = true
						result.SDPCaptureToPublicationUpperNS = published - at.UnixNano()
					}
				})
				report, err := json.Marshal(result)
				require.NoError(t, err)
				t.Logf("EBPF_MEASUREMENT %s", report)
			})
		}
	}
}

func admissionHeapCounters(t *testing.T, address string) (uint64, uint64) {
	t.Helper()
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + address + "/debug/pprof/heap?debug=1")
	require.NoError(t, err)
	contents, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	require.NoError(t, err)
	require.NoError(t, closeErr)
	require.Equal(t, http.StatusOK, response.StatusCode)
	value := func(name string) uint64 {
		pattern := regexp.MustCompile(`(?m)^# ` + name + ` = ([0-9]+)$`)
		match := pattern.FindSubmatch(contents)
		require.Len(t, match, 2, "missing heap counter %s", name)
		n, err := strconv.ParseUint(string(match[1]), 10, 64)
		require.NoError(t, err)
		return n
	}
	return value("TotalAlloc"), value("Mallocs")
}

func admissionReadPackets(t *testing.T, root string, visit func([]byte, time.Time)) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".pcap") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		reader, err := pcapgo.NewReader(file)
		if err != nil {
			closeErr := file.Close()
			if closeErr != nil {
				return fmt.Errorf("%v; close: %w", err, closeErr)
			}
			return err
		}
		for {
			data, ci, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				closeErr := file.Close()
				if closeErr != nil {
					return fmt.Errorf("%v; close: %w", err, closeErr)
				}
				return err
			}
			visit(data, ci.Timestamp)
		}
		return file.Close()
	}))
}

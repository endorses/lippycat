//go:build li

package li

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// correlationCSeq distinguishes a valid zero from absent or malformed metadata.
// Raw signaling is authoritative. Legacy metadata can identify positive CSeqs;
// zero requires the actual header because zero is also the unparsed default.
func correlationCSeq(pkt *types.PacketDisplay) (uint64, string, bool) {
	if pkt == nil || pkt.VoIPData == nil {
		return 0, "", false
	}
	v := pkt.VoIPData
	headers, invalid := correlationHeaders(pkt)
	if invalid {
		return 0, "", false
	}
	values := headers["cseq"]
	if len(v.RawSIP) != 0 || len(values) != 0 {
		value, present, conflict := oneCorrelationHeader(values)
		if !present || conflict {
			return 0, "", false
		}
		fields := strings.Fields(value)
		if len(fields) != 2 || fields[0] == "" {
			return 0, "", false
		}
		for _, digit := range fields[0] {
			if digit < '0' || digit > '9' {
				return 0, "", false
			}
		}
		number, err := strconv.ParseUint(fields[0], 10, 31)
		if err != nil {
			return 0, "", false
		}
		return number, fields[1], true
	}
	if v.CSeqNumber == 0 || v.CSeqNumber >= 1<<31 {
		return 0, "", false
	}
	method := v.CSeqMethod
	if method == "" && v.Status == 0 {
		method = v.Method
	}
	return v.CSeqNumber, method, method != ""
}

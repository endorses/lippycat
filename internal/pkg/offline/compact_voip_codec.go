package offline

import (
	"fmt"
	"reflect"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// encodeCompactOverrides specializes the common VoIP-only override. Admission
// still measures the complete owned graph, independently of the override mask.
// The generic encoder remains the frozen oracle and handles mixed protocols.
func encodeCompactOverrides(value compactOverrides, max uint64) ([]byte, error) {
	m := value.Metadata
	if m.VoIP == nil || m.DNS != nil || m.Email != nil || m.TLS != nil || m.HTTP != nil || m.RADIUS != nil {
		return encodeCompactValue(value, max)
	}
	if max > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("invalid compact value or budget")
	}
	v := reflect.ValueOf(value)
	memory := uint64(v.Type().Size())
	if err := measureMemory(v, &memory, max); err != nil {
		return nil, err
	}
	if memory > max {
		return nil, fmt.Errorf("compact value exceeds memory budget")
	}
	e := compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max}}}
	e.voipOverride(value.Mask, m.VoIP)
	if e.err != nil {
		return nil, e.err
	}
	e = compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max, data: make([]byte, 0, int(e.size))}}}
	e.voipOverride(value.Mask, m.VoIP)
	return e.data, e.err
}

func (e *compactRowEncoder) generic(value any) {
	if e.err == nil {
		e.err = e.value(reflect.ValueOf(value))
	}
}

// Keep the exact schema order from compactFieldNames[VoIPMetadata]. Containers
// use the generic codec to preserve sorted maps and nil/empty distinctions.
func (e *compactRowEncoder) voipOverride(mask uint8, p *types.VoIPMetadata) {
	e.uint(uint64(mask), 1)
	e.uint(1, 1) // nonnil VoIP pointer
	e.text(p.CallID)
	e.text(p.Method)
	e.text(p.CSeqMethod)
	e.uint(uint64(p.Status), 8)
	for _, s := range [...]string{p.From, p.To, p.FromTag, p.ToTag, p.User, p.ContentType, p.Body} {
		e.text(s)
	}
	e.generic(p.Headers)
	e.generic(p.RawSIP)
	e.text(p.IMSI)
	e.text(p.IMEI)
	e.generic(p.AccessNetworkInfo)
	e.text(p.VisitedNetworkID)
	e.boolean(p.IsRTP)
	e.uint(uint64(p.SSRC), 4)
	e.uint(uint64(p.PayloadType), 1)
	e.uint(uint64(p.SequenceNum), 2)
	e.uint(uint64(p.SeqNumber), 2)
	e.uint(uint64(p.Timestamp), 4)
	e.text(p.Codec)
	e.text(p.MergeFromCallID)
	e.uint(p.CSeqNumber, 8)
	e.text(p.ViaBranch)
	e.uint(0, 5) // nil DNS, Email, TLS, HTTP and RADIUS pointers
}

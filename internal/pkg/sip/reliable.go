package sip

import (
	"strconv"
	"strings"
)

// ReliableHeaders contains only the bounded numeric linkage used by delayed
// INVITE offer recovery. It deliberately retains no raw header values.
type ReliableHeaders struct {
	ResponseValid bool
	RSeq          uint32
	RAckValid     bool
	RAckRSeq      uint32
	RAckCSeq      uint32
}

// ReliableHeaderDuplicates records repeated singleton occurrences independently
// of semantic validity. Folded continuations are not duplicates.
type ReliableHeaderDuplicates struct {
	CSeq bool
	RSeq bool
	RAck bool
}

// ReliableHeaderConflicts identifies singleton evidence that is conflicting or
// malformed. Valid equivalent numbers (including leading zeroes) compare equal;
// methods are validated SIP tokens and compare case sensitively.
type ReliableHeaderConflicts struct {
	CSeq bool
	RSeq bool
	RAck bool
}

// ReliableHeaderEvidence contains bounded proof metadata, never raw values.
// CSeqMin/Max include only fully valid occurrences. CSeqBoundsValid requires
// every occurrence valid and a single method; conflicting numbers still provide
// a range. CSeqValid additionally requires a single sequence number.
type ReliableHeaderEvidence struct {
	Conflicts          ReliableHeaderConflicts
	CSeqValid          bool
	CSeqBoundsValid    bool
	CSeqMin, CSeqMax   uint32
	CSeqMethodConflict bool
	CSeqMalformed      bool
}

// ParseReliableHeadersWithEvidence accepts identical valid repetitions while
// rejecting conflicting or malformed occurrences, including an invalid earlier
// value hidden by the ordinary last-line representation.
func ParseReliableHeadersWithEvidence(headers map[string]string, evidence ReliableHeaderEvidence) ReliableHeaders {
	return ParseReliableHeaders(headers, ReliableHeaderDuplicates{
		CSeq: evidence.Conflicts.CSeq, RSeq: evidence.Conflicts.RSeq, RAck: evidence.Conflicts.RAck,
	})
}

// ParseReliableHeaders validates RFC 3262 linkage. An INVITE response uses
// Require: 100rel and one RSeq; PRACK references that response's INVITE CSeq,
// independently of its own CSeq and Via branch. SIP methods are case sensitive.
// Parsed message consumers must pass SIPEvent.DuplicateReliableHeaders. The
// optional argument retains support for callers validating standalone headers.
func ParseReliableHeaders(headers map[string]string, duplicates ...ReliableHeaderDuplicates) ReliableHeaders {
	var result ReliableHeaders
	var repeated ReliableHeaderDuplicates
	for _, duplicate := range duplicates {
		repeated.CSeq = repeated.CSeq || duplicate.CSeq
		repeated.RSeq = repeated.RSeq || duplicate.RSeq
		repeated.RAck = repeated.RAck || duplicate.RAck
	}
	if repeated.CSeq {
		return result
	}
	cseq := strings.Fields(headers["cseq"])
	if len(cseq) != 2 {
		return result
	}
	if _, valid := sequenceNumber(cseq[0], 31, false); !valid {
		return result
	}
	if cseq[1] == "INVITE" && !repeated.RSeq {
		required, valid := reliableRequired(headers["require"])
		if number, numberValid := sequenceNumber(headers["rseq"], 32, true); valid && required && numberValid {
			result.ResponseValid, result.RSeq = true, number
		}
	}
	if cseq[1] == "PRACK" && !repeated.RAck {
		fields := strings.Fields(headers["rack"])
		if len(fields) != 3 || fields[2] != "INVITE" {
			return result
		}
		rseq, rseqValid := sequenceNumber(fields[0], 32, true)
		referenced, cseqValid := sequenceNumber(fields[1], 31, false)
		if rseqValid && cseqValid {
			result.RAckValid, result.RAckRSeq, result.RAckCSeq = true, rseq, referenced
		}
	}
	return result
}

func reliableRequired(raw string) (bool, bool) {
	if raw == "" {
		return false, true
	}
	found := false
	for _, option := range strings.Split(raw, ",") {
		option = strings.TrimSpace(option)
		if !IsRequestMethod(option) {
			return false, false
		}
		if option == "100rel" {
			found = true
		}
	}
	return found, true
}

func sequenceNumber(raw string, bits int, positive bool) (uint32, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseUint(raw, 10, bits)
	return uint32(number), err == nil && (!positive || number != 0)
}

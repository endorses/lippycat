package sip

import "strings"

// The accumulator retains one parsed value per singleton while scanning the
// headers. Its storage is independent of the number of duplicate occurrences.
type reliableEvidenceAccumulator struct {
	evidence                                   ReliableHeaderEvidence
	cseqSeen, rseqSeen, rackSeen               bool
	cseqNumber, rseqNumber, rackRSeq, rackCSeq uint32
	cseqMethod, rackMethod                     string
	validCSeqSeen                              bool
}

func (a *reliableEvidenceAccumulator) observe(name, value string) {
	switch name {
	case "cseq":
		fields := strings.Fields(value)
		valid := len(fields) == 2
		var number uint32
		var method string
		if valid {
			var numberValid bool
			number, numberValid = sequenceNumber(fields[0], 31, false)
			method = fields[1]
			valid = numberValid && IsRequestMethod(method)
		}
		if !valid {
			a.evidence.CSeqMalformed = true
			a.evidence.Conflicts.CSeq = true
		} else {
			if !a.validCSeqSeen {
				a.evidence.CSeqMin, a.evidence.CSeqMax = number, number
				a.cseqNumber, a.cseqMethod = number, method
				a.validCSeqSeen = true
			} else {
				if number < a.evidence.CSeqMin {
					a.evidence.CSeqMin = number
				}
				if number > a.evidence.CSeqMax {
					a.evidence.CSeqMax = number
				}
				if method != a.cseqMethod {
					a.evidence.CSeqMethodConflict = true
				}
				if number != a.cseqNumber || method != a.cseqMethod {
					a.evidence.Conflicts.CSeq = true
				}
			}
		}
		a.cseqSeen = true
	case "rseq":
		number, valid := sequenceNumber(value, 32, true)
		if a.rseqSeen && (!valid || a.evidence.RSeqMalformed || number != a.rseqNumber) {
			a.evidence.Conflicts.RSeq = true
		}
		a.evidence.RSeqMalformed = a.evidence.RSeqMalformed || !valid
		if !a.rseqSeen {
			a.rseqNumber = number
		}
		a.rseqSeen = true
	case "rack":
		fields := strings.Fields(value)
		valid := len(fields) == 3
		var rseq, cseq uint32
		var method string
		if valid {
			var rseqValid, cseqValid bool
			rseq, rseqValid = sequenceNumber(fields[0], 32, true)
			cseq, cseqValid = sequenceNumber(fields[1], 31, false)
			method = fields[2]
			valid = rseqValid && cseqValid && IsRequestMethod(method)
		}
		if a.rackSeen && (!valid || a.evidence.RAckMalformed || rseq != a.rackRSeq || cseq != a.rackCSeq || method != a.rackMethod) {
			a.evidence.Conflicts.RAck = true
		}
		a.evidence.RAckMalformed = a.evidence.RAckMalformed || !valid
		if !a.rackSeen {
			a.rackRSeq, a.rackCSeq, a.rackMethod = rseq, cseq, method
		}
		a.rackSeen = true
	}
}

func (a *reliableEvidenceAccumulator) result() ReliableHeaderEvidence {
	a.evidence.CSeqBoundsValid = a.validCSeqSeen && !a.evidence.CSeqMalformed && !a.evidence.CSeqMethodConflict
	a.evidence.CSeqValid = a.evidence.CSeqBoundsValid && !a.evidence.Conflicts.CSeq
	return a.evidence
}

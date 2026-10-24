package smsflow

import "bytes"

// HasTrailingPayload reports inseparable content beyond one parsed SIP message.
// bodyLength must be the exact binary body length returned by the shared SIP
// parser. Only trailing CRLF pairs are allowed; binary body bytes are untouched.
// Missing headers or an incomplete body return false: unavailable raw framing
// cannot discredit supplied metadata, and callers handle decode failures.
func HasTrailingPayload(payload []byte, bodyLength int) bool {
	if bodyLength < 0 {
		return false
	}
	headerEnd, separatorLength := bytes.Index(payload, []byte("\r\n\r\n")), 4
	if headerEnd < 0 {
		headerEnd, separatorLength = bytes.Index(payload, []byte("\n\n")), 2
	}
	if headerEnd < 0 {
		return false
	}
	bodyStart := headerEnd + separatorLength
	if bodyLength > len(payload)-bodyStart {
		return false
	}
	tail := payload[bodyStart+bodyLength:]
	for len(tail) >= 2 && tail[0] == '\r' && tail[1] == '\n' {
		tail = tail[2:]
	}
	return len(tail) != 0
}

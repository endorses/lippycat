package voip

import (
	"testing"
)

// Fuzz tests for SIP parsing functions
// These tests help identify edge cases and potential crashes in parsing logic

// FuzzParseSipHeaders tests the SIP header parsing function with arbitrary input
func FuzzParseSipHeaders(f *testing.F) {
	// Seed corpus with valid SIP messages
	f.Add([]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123\r\nFrom: Alice <sip:alice@example.com>\r\nTo: Bob <sip:bob@example.com>\r\n\r\nBody"))
	f.Add([]byte("SIP/2.0 200 OK\r\nCall-ID: def456\r\n\r\n"))
	f.Add([]byte("REGISTER sip:registrar.example.com SIP/2.0\r\n\r\n"))
	f.Add([]byte("BYE sip:user@host SIP/2.0\r\nCall-ID: test\r\n\r\n"))

	// Malformed inputs
	f.Add([]byte(""))
	f.Add([]byte("\r\n"))
	f.Add([]byte(":::"))
	f.Add([]byte("Header-Without-Colon\r\n"))
	f.Add([]byte(":\r\n"))
	f.Add([]byte(": value\r\n"))
	f.Add([]byte("Key:\r\n"))

	// Very long inputs
	f.Add(make([]byte, 100000))

	// Unicode and binary data
	f.Add([]byte("INVITE sip:日本語@example.com SIP/2.0\r\n\r\n"))
	f.Add([]byte{0x00, 0xFF, 0xFE, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		// parseSipHeaders should not panic on any input
		headers, body := parseSipHeaders(data)

		// Basic sanity checks - results should be valid types
		_ = headers
		_ = body
	})
}

// FuzzParseHeaderLineBytes tests individual header line parsing
func FuzzParseHeaderLineBytes(f *testing.F) {
	// Valid headers
	f.Add([]byte("Call-ID: abc123"))
	f.Add([]byte("From: Alice <sip:alice@example.com>"))
	f.Add([]byte("To: Bob <sip:bob@example.com>;tag=xyz"))
	f.Add([]byte("Content-Length: 1234"))
	f.Add([]byte("Via: SIP/2.0/UDP 192.168.1.1:5060"))
	f.Add([]byte("i: compactcallid")) // Compact form
	f.Add([]byte("f: compact-from"))  // Compact form
	f.Add([]byte("t: compact-to"))    // Compact form
	f.Add([]byte("l: 0"))             // Compact form

	// Edge cases
	f.Add([]byte(""))
	f.Add([]byte(":"))
	f.Add([]byte(": value"))
	f.Add([]byte("key:"))
	f.Add([]byte("key: "))
	f.Add([]byte("   key  :  value  "))
	f.Add([]byte("key:value:with:colons"))
	f.Add([]byte("Key-With-Dashes: value"))

	// Malformed
	f.Add([]byte("no colon here"))
	f.Add([]byte("\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		key, value := parseHeaderLineBytes(data)
		_ = key
		_ = value
	})
}

// FuzzExtractUserFromSIPURI tests SIP URI user extraction
func FuzzExtractUserFromSIPURI(f *testing.F) {
	// Valid SIP URIs
	f.Add("sip:alice@example.com")
	f.Add("sips:bob@secure.example.com")
	f.Add("sip:+1234567890@carrier.com")
	f.Add("<sip:user@host>")
	f.Add("Alice <sip:alice@example.com>")
	f.Add("\"Bob Smith\" <sip:bob.smith@example.com>")
	f.Add("sip:user@host:5060")
	f.Add("sip:user@host;transport=tcp")
	f.Add("sip:user:password@host")

	// Edge cases
	f.Add("")
	f.Add("sip:")
	f.Add("sip:@")
	f.Add("sip:user") // No @ symbol
	f.Add("not-a-sip-uri")
	f.Add("mailto:user@example.com")
	f.Add("sip:@host")
	f.Add("sips:")

	// Nested and complex
	f.Add("<sip:user@host>;tag=abc")
	f.Add("sip:user@host?header=value")
	f.Add("sip:user@host;param=value?header=value")

	f.Fuzz(func(t *testing.T, uri string) {
		user := extractUserFromSIPURI(uri)
		_ = user
	})
}

// FuzzExtractFullSIPURI tests full SIP URI extraction
func FuzzExtractFullSIPURI(f *testing.F) {
	// Valid inputs
	f.Add("sip:user@host")
	f.Add("<sip:user@host>")
	f.Add("Alice <sip:alice@example.com>")
	f.Add("sip:user@host;transport=tcp")
	f.Add("<sip:user@host>;tag=abc")
	f.Add("\"Name\" <sips:user@host>")

	// Edge cases
	f.Add("")
	f.Add("<>")
	f.Add("<sip:>")
	f.Add("no-uri-here")
	f.Add("<<nested>>")
	f.Add("<unclosed")
	f.Add("unopened>")

	f.Fuzz(func(t *testing.T, header string) {
		uri := extractFullSIPURI(header)
		_ = uri
	})
}

// FuzzExtractSipResponseCode tests SIP response code extraction
func FuzzExtractSipResponseCode(f *testing.F) {
	// Valid responses
	f.Add([]byte("SIP/2.0 100 Trying"))
	f.Add([]byte("SIP/2.0 180 Ringing"))
	f.Add([]byte("SIP/2.0 200 OK"))
	f.Add([]byte("SIP/2.0 404 Not Found"))
	f.Add([]byte("SIP/2.0 500 Server Error"))
	f.Add([]byte("SIP/2.0 600 Busy Everywhere"))

	// Edge cases
	f.Add([]byte(""))
	f.Add([]byte("SIP/2.0 "))
	f.Add([]byte("SIP/2.0 99"))          // Two digit
	f.Add([]byte("SIP/2.0 9999"))        // Four digit
	f.Add([]byte("SIP/2.0 abc"))         // Non-numeric
	f.Add([]byte("SIP/2.0"))             // No space after version
	f.Add([]byte("HTTP/1.1 200 OK"))     // Not SIP
	f.Add([]byte("INVITE sip: SIP/2.0")) // Request, not response

	// Boundary cases
	f.Add([]byte("SIP/2.0 000 Zero"))
	f.Add([]byte("SIP/2.0 999 Max"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		code := extractSipResponseCode(payload)

		// If a code was extracted, it should be a valid 3-digit code
		if code != 0 {
			if code < 100 || code > 999 {
				t.Errorf("Invalid response code: %d", code)
			}
		}
	})
}

// FuzzIsSipStartLine tests SIP start line validation
func FuzzIsSipStartLine(f *testing.F) {
	// Valid start lines
	f.Add("INVITE sip:user@host SIP/2.0")
	f.Add("BYE sip:user@host SIP/2.0")
	f.Add("ACK sip:user@host SIP/2.0")
	f.Add("CANCEL sip:user@host SIP/2.0")
	f.Add("OPTIONS sip:user@host SIP/2.0")
	f.Add("REGISTER sip:registrar SIP/2.0")
	f.Add("SIP/2.0 200 OK")
	f.Add("SIP/2.0 100 Trying")

	// Invalid start lines
	f.Add("")
	f.Add("UNKNOWN sip:user@host SIP/2.0")
	f.Add("INVITE sip:user@host") // Missing SIP/2.0
	f.Add("HTTP/1.1 200 OK")      // Wrong protocol
	f.Add("sip:user@host")        // Just a URI
	f.Add("   INVITE")            // Leading whitespace

	f.Fuzz(func(t *testing.T, line string) {
		result := isSipStartLine(line)
		_ = result
	})
}

// FuzzExtractTagFromHeader tests tag parameter extraction
func FuzzExtractTagFromHeader(f *testing.F) {
	// Valid headers with tags
	f.Add("Alice <sip:alice@example.com>;tag=abc123")
	f.Add("<sip:user@host>;tag=xyz789")
	f.Add("sip:user@host;tag=simple")
	f.Add("<sip:user@host>;tag=1234;other=param")
	f.Add(";tag=just-tag")

	// Case variations
	f.Add("<sip:user@host>;TAG=uppercase")
	f.Add("<sip:user@host>;Tag=mixed")

	// No tag
	f.Add("Alice <sip:alice@example.com>")
	f.Add("<sip:user@host>")
	f.Add("sip:user@host")
	f.Add("")

	// Edge cases
	f.Add(";tag=")
	f.Add(";tag")
	f.Add("tag=notparam")

	f.Fuzz(func(t *testing.T, header string) {
		tag := extractTagFromHeader(header)
		_ = tag
	})
}

// FuzzNormalizeHeaderName tests header name normalization
func FuzzNormalizeHeaderName(f *testing.F) {
	// Compact form headers
	f.Add("i")
	f.Add("f")
	f.Add("t")
	f.Add("v")
	f.Add("c")
	f.Add("m")
	f.Add("l")

	// Full form headers
	f.Add("call-id")
	f.Add("from")
	f.Add("to")
	f.Add("via")
	f.Add("contact")
	f.Add("content-length")

	// Unknown/other headers
	f.Add("")
	f.Add("x-custom")
	f.Add("user-agent")
	f.Add("unknown")

	f.Fuzz(func(t *testing.T, header string) {
		normalized := normalizeHeaderName(header)
		_ = normalized
	})
}

// FuzzExtractURIFromHeader tests URI extraction from headers
func FuzzExtractURIFromHeader(f *testing.F) {
	// Valid URIs in headers
	f.Add("Alice <sip:alice@domain.com>;tag=123")
	f.Add("sip:+49123456789@carrier.com")
	f.Add("<sips:secure@example.com>")
	f.Add("\"Display Name\" <sip:user@host>")

	// Edge cases
	f.Add("")
	f.Add("<>")
	f.Add("no-uri")
	f.Add("sip:user")
	f.Add("<sip:>")

	f.Fuzz(func(t *testing.T, header string) {
		uri := extractURIFromSIPHeader(header)
		_ = uri
	})
}

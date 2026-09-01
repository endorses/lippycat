//go:build hunter || tap || all

package hunter

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractSIPHeadersCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    sipHeaders
	}{
		{
			name: "long names mixed case and CRLF",
			payload: []byte("MESSAGE sip:target@example.invalid SIP/2.0\r\n" +
				"fRoM: <sip:origin@example.invalid>\r\n" +
				"tO: <sip:target@example.invalid>\r\n" +
				"p-AsSeRtEd-IdEnTiTy: <sip:asserted@example.invalid>\r\n" +
				"P-pReFeRrEd-IdEnTiTy: <sip:preferred@example.invalid>\r\n" +
				"p-CaLlEd-PaRtY-iD: <sip:called@example.invalid>\r\n" +
				"aUtHoRiZaTiOn: Digest username=\"synthetic\"\r\n" +
				"cOnTaCt: <sip:device@example.invalid>\r\n\r\nignored body"),
			want: sipHeaders{
				from: []byte("<sip:origin@example.invalid>"), to: []byte("<sip:target@example.invalid>"),
				pAssertedIdentity: []byte("<sip:asserted@example.invalid>"), pPreferredIdentity: []byte("<sip:preferred@example.invalid>"),
				pCalledPartyID: []byte("<sip:called@example.invalid>"), requestURI: []byte("sip:target@example.invalid"),
				authorization: []byte("Digest username=\"synthetic\""), contact: []byte("<sip:device@example.invalid>"),
			},
		},
		{
			name: "compact headers and LF",
			payload: []byte("INVITE sip:compact@example.invalid SIP/2.0\n" +
				"F: <sip:from@example.invalid>\nT:\t<sip:to@example.invalid>\nM: <sip:contact@example.invalid>\n\nbody"),
			want: sipHeaders{from: []byte("<sip:from@example.invalid>"), to: []byte("<sip:to@example.invalid>"), requestURI: []byte("sip:compact@example.invalid"), contact: []byte("<sip:contact@example.invalid>")},
		},
		{
			name:    "response has no request URI",
			payload: []byte("SIP/2.0 200 OK\r\nFrom: <sip:a@example.invalid>\r\nTo: <sip:b@example.invalid>\r\n\r\n"),
			want:    sipHeaders{from: []byte("<sip:a@example.invalid>"), to: []byte("<sip:b@example.invalid>")},
		},
		{
			name:    "empty and malformed lines",
			payload: []byte("INVITE\r\nFrom\r\nTo : not-a-header\r\nAuthorization\r\n\r\nContact: <sip:body@example.invalid>"),
			want:    sipHeaders{},
		},
		{
			name:    "header body boundary",
			payload: []byte("OPTIONS sip:service@example.invalid SIP/2.0\r\nFrom: <sip:header@example.invalid>\r\n\r\nTo: <sip:body@example.invalid>\r\n"),
			want:    sipHeaders{from: []byte("<sip:header@example.invalid>"), requestURI: []byte("sip:service@example.invalid")},
		},
		{
			name:    "repeated header keeps last value",
			payload: []byte("INVITE sip:b@example.invalid SIP/2.0\nFrom: <sip:first@example.invalid>\nFrom: <sip:last@example.invalid>\n"),
			want:    sipHeaders{from: []byte("<sip:last@example.invalid>"), requestURI: []byte("sip:b@example.invalid")},
		},
		{
			name:    "empty recognized headers",
			payload: []byte("INVITE sip:b@example.invalid SIP/2.0\r\nFrom:\r\nTo: \t\r\nContact:\r\n\r\n"),
			want:    sipHeaders{requestURI: []byte("sip:b@example.invalid")},
		},
		{
			name:    "mixed supported line endings",
			payload: []byte("INVITE sip:b@example.invalid SIP/2.0\r\nFrom: <sip:a@example.invalid>\nTo: <sip:b@example.invalid>\r\n\r\n"),
			want:    sipHeaders{from: []byte("<sip:a@example.invalid>"), to: []byte("<sip:b@example.invalid>"), requestURI: []byte("sip:b@example.invalid")},
		},
		{
			name:    "request line has too few tokens",
			payload: []byte("INVITE SIP/2.0\r\nFrom: <sip:a@example.invalid>\r\n\r\n"),
			want:    sipHeaders{from: []byte("<sip:a@example.invalid>")},
		},
		{
			name:    "request line has too many tokens",
			payload: []byte("INVITE sip:b@example.invalid SIP/2.0 extra\r\n\r\n"),
			want:    sipHeaders{},
		},
		{
			name:    "request line preserves unicode whitespace compatibility",
			payload: []byte("INVITE\u00a0sip:b@example.invalid\u00a0SIP/2.0\r\n\r\n"),
			want:    sipHeaders{requestURI: []byte("sip:b@example.invalid")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, extractSIPHeaders(tt.payload))
		})
	}
}

func TestExtractSIPHeadersOversizedHeaderIsBoundedByPayload(t *testing.T) {
	value := bytes.Repeat([]byte{'x'}, 1<<20)
	payload := append([]byte("INVITE sip:bounded@example.invalid SIP/2.0\r\nFrom: "), value...)
	payload = append(payload, []byte("\r\n\r\nFrom: <sip:body@example.invalid>")...)

	headers := extractSIPHeaders(payload)
	require.Len(t, headers.from, len(value))
	require.Equal(t, []byte("sip:bounded@example.invalid"), headers.requestURI)
}

func FuzzExtractSIPHeaders(f *testing.F) {
	seeds := [][]byte{
		{0x80, 0xc8, 0, 6, 0, 0, 0, 1, 0xff, 0x00, '\r', '\n'},
		[]byte("INVITE sip:truncated@example.invalid SIP/2.0\r\nFrom:"),
		[]byte("MESSAGE sip:b@example.invalid SIP/2.0\nFrOm: one\nf: two\n\nFrom: body"),
		[]byte("SIP/2.0 401 Unauthorized\r\naUtHoRiZaTiOn: Digest username=\"x\"\r\n\r\n"),
		append([]byte("INVITE sip:large@example.invalid SIP/2.0\r\nContact: "), bytes.Repeat([]byte{'z'}, 64<<10)...),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		headers := extractSIPHeaders(payload)
		// Every view must be bounded by the supplied input. This also catches
		// accidental unbounded growth derived from malformed length-like data.
		for _, value := range [][]byte{headers.from, headers.to, headers.pAssertedIdentity, headers.pPreferredIdentity, headers.pCalledPartyID, headers.requestURI, headers.authorization, headers.contact} {
			require.LessOrEqual(t, len(value), len(payload))
		}
	})
}

func BenchmarkExtractSIPHeaders(b *testing.B) {
	cases := map[string][]byte{
		"representative": []byte("INVITE sip:target@example.invalid SIP/2.0\r\nFrom: <sip:origin@example.invalid>;tag=1\r\nTo: <sip:target@example.invalid>\r\nP-Asserted-Identity: <sip:asserted@example.invalid>\r\nP-Preferred-Identity: <sip:preferred@example.invalid>\r\nP-Called-Party-ID: <sip:called@example.invalid>\r\nAuthorization: Digest username=\"synthetic\"\r\nContact: <sip:device@example.invalid>\r\nContent-Length: 0\r\n\r\n"),
		"minimal":        []byte("OPTIONS sip:service@example.invalid SIP/2.0\r\n\r\n"),
		"no_match_text":  []byte("this is ordinary text with no protocol headers\nsecond line\n"),
		"binary_media":   {0x80, 0x00, 0, 1, 0, 0, 0, 1, 0x12, 0x34, 0x56, 0x78, 0xff, 0x00, 0xfe},
	}
	for name, payload := range cases {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = extractSIPHeaders(payload)
			}
		})
	}
}

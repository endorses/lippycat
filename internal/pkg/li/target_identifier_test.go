//go:build li

package li

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalTargetIdentifierSchemaChoices(t *testing.T) {
	cases := []struct {
		name            string
		kind            TargetType
		value, expected string
	}{
		{"sip escaping", TargetTypeSIPURI, "sip:subscriber&one@example.invalid", "<sipUri>sip:subscriber&amp;one@example.invalid</sipUri>"},
		{"sips apostrophe", TargetTypeSIPURI, "sips:sub'one@example.invalid", "<sipUri>sips:sub&#39;one@example.invalid</sipUri>"},
		{"tel", TargetTypeTELURI, "tel:+1234567890", "<telUri>tel:+1234567890</telUri>"},
		{"legacy tel digits", TargetTypeTELURI, "1234567890", "<e164Number>1234567890</e164Number>"},
		{"legacy tel plus", TargetTypeTELURI, "+1234567890", "<e164Number>1234567890</e164Number>"},
		{"e164", TargetTypeE164, "1234567890", "<e164Number>1234567890</e164Number>"},
		{"nai escaping", TargetTypeNAI, "subscriber&one@example.invalid", "<nai>subscriber&amp;one@example.invalid</nai>"},
		{"ipv4", TargetTypeIPv4Address, "192.0.2.1", "<ipv4Address>192.0.2.1</ipv4Address>"},
		{"ipv4 cidr", TargetTypeIPv4CIDR, "192.0.2.0/24", `<ipv4Cidr><IPv4CIDR xmlns="http://uri.etsi.org/03280/common/2017/07">192.0.2.0/24</IPv4CIDR></ipv4Cidr>`},
		{"ipv6", TargetTypeIPv6Address, "2001:db8::1", "<ipv6Address>2001:0db8:0000:0000:0000:0000:0000:0001</ipv6Address>"},
		{"ipv6 cidr", TargetTypeIPv6CIDR, "2001:db8::/64", "<ipv6Cidr>2001:0db8:0000:0000:0000:0000:0000:0000/64</ipv6Cidr>"},
		{"imsi", TargetTypeIMSI, "001010123456789", "<imsi>001010123456789</imsi>"},
		{"imei", TargetTypeIMEI, "12345678901234", "<imei>12345678901234</imei>"},
		{"mac hex", TargetTypeMACAddress, "001122AABBCC", "<macAddress>00:11:22:aa:bb:cc</macAddress>"},
		{"mac colon", TargetTypeMACAddress, "00:11:22:aa:bb:cc", "<macAddress>00:11:22:aa:bb:cc</macAddress>"},
		{"radius hex", TargetTypeRADIUSAttribute, "010673796e74", "<radiusAttribute>010673796E74</radiusAttribute>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MarshalTargetIdentifier(TargetIdentity{Type: tc.kind, Value: tc.value})
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
			require.NotContains(t, got, "<?xml")
			validateTargetIdentifierSchema(t, got)
		})
	}
}

func validateTargetIdentifierSchema(t *testing.T, content string) {
	t.Helper()
	xmllint, err := exec.LookPath("xmllint")
	require.NoError(t, err, "xmllint is required for target identifier schema tests")
	core, err := filepath.Abs(filepath.Join("x1", "xsd", "TS_103_221_01.xsd"))
	require.NoError(t, err)
	var escaped strings.Builder
	require.NoError(t, xml.EscapeText(&escaped, []byte(core)))
	const namespace = "http://uri.etsi.org/03221/X1/2017/10"
	harness := fmt.Sprintf(`<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:x1="%s" targetNamespace="%s" elementFormDefault="qualified"><xs:include schemaLocation="%s"/><xs:element name="targetIdentifier" type="x1:TargetIdentifier"/></xs:schema>`, namespace, namespace, escaped.String())
	directory := t.TempDir()
	schemaPath, document := filepath.Join(directory, "target.xsd"), filepath.Join(directory, "target.xml")
	require.NoError(t, os.WriteFile(schemaPath, []byte(harness), 0600))
	require.NoError(t, os.WriteFile(document, []byte(`<targetIdentifier xmlns="`+namespace+`">`+content+`</targetIdentifier>`), 0600))
	output, err := exec.Command(xmllint, "--noout", "--schema", schemaPath, document).CombinedOutput()
	require.NoError(t, err, "%s", output)
}

func TestMarshalTargetIdentifierRejectsInvalidValues(t *testing.T) {
	cases := []TargetIdentity{
		{Type: TargetTypeSIPURI, Value: "https:subscriber@example.invalid"},
		{Type: TargetTypeSIPURI, Value: "sip:subscriber</sipUri><imsi>001010123456789</imsi>"},
		{Type: TargetTypeSIPURI, Value: "sip:subscriber\x00@example.invalid"},
		{Type: TargetTypeTELURI, Value: "tel:"},
		{Type: TargetTypeE164, Value: "+1234567890"},
		{Type: TargetTypeE164, Value: "1234567890123456"},
		{Type: TargetTypeNAI, Value: "subscriber\x00@example.invalid"},
		{Type: TargetTypeNAI, Value: "subscriber\ufffe@example.invalid"},
		{Type: TargetTypeNAI, Value: "subscriber\xff@example.invalid"},
		{Type: TargetTypeIPv4Address, Value: "2001:db8::1"},
		{Type: TargetTypeIPv6Address, Value: "192.0.2.1"},
		{Type: TargetTypeIPv6Address, Value: "fe80::1%capture0"},
		{Type: TargetTypeIPv4CIDR, Value: "192.0.2.0/33"},
		{Type: TargetTypeIPv6CIDR, Value: "2001:db8::/129"},
		{Type: TargetTypeIPv6CIDR, Value: "::/0"},
		{Type: TargetTypeIMSI, Value: "12345"},
		{Type: TargetTypeIMEI, Value: "123456789012345"},
		{Type: TargetTypeMACAddress, Value: "001122ZZBBCC"},
		{Type: TargetTypeMACAddress, Value: "00:11:22:33:44"},
		{Type: TargetTypeRADIUSAttribute, Value: "010473"},
		{Type: TargetTypeRADIUSAttribute, Value: "ZZ"},
		{Type: TargetType(999), Value: "private-value"},
	}
	for _, target := range cases {
		t.Run(fmt.Sprintf("%s/%x", target.Type, target.Value), func(t *testing.T) {
			got, err := MarshalTargetIdentifier(target)
			require.ErrorIs(t, err, ErrInvalidTargetIdentifier)
			require.Empty(t, got)
			require.NotContains(t, err.Error(), target.Value, "serialization errors must not expose identity content")
		})
	}
	for _, kind := range []TargetType{TargetTypeSIPURI, TargetTypeTELURI, TargetTypeE164, TargetTypeNAI, TargetTypeIPv4Address, TargetTypeIPv6Address, TargetTypeIPv4CIDR, TargetTypeIPv6CIDR, TargetTypeIMSI, TargetTypeIMEI, TargetTypeMACAddress, TargetTypeRADIUSAttribute} {
		_, err := MarshalTargetIdentifier(TargetIdentity{Type: kind})
		require.ErrorIs(t, err, ErrInvalidTargetIdentifier)
	}
}

func TestMatchedTargetFormatAndUsernameOmission(t *testing.T) {
	for input, expected := range map[string]MatchedTargetFormat{"": MatchedTargetFormatBare, "bare": MatchedTargetFormatBare, "target-identifier": MatchedTargetFormatTargetIdentifier} {
		got, err := ParseMatchedTargetFormat(input)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	}
	for _, input := range []string{"xml", "target_identifier", "BARE", " bare"} {
		_, err := ParseMatchedTargetFormat(input)
		require.Error(t, err)
	}
	got, err := MarshalTargetIdentifier(TargetIdentity{Type: TargetTypeUsername, Value: "subscriber"})
	require.NoError(t, err)
	require.Empty(t, got)
}

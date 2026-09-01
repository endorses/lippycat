//go:build hunter || tap || all

package hunter

import "testing"

func TestExtractSMTPFieldsAcceptsNilMetadata(t *testing.T) {
	filter := &ApplicationFilter{}
	sender, recipient, subject := filter.extractSMTPFields([]byte("MAIL FROM:<sender@example.test>\r\n"), nil)
	if sender != "sender@example.test" || recipient != "" || subject != "" {
		t.Fatalf("unexpected fields: sender=%q recipient=%q subject=%q", sender, recipient, subject)
	}
}

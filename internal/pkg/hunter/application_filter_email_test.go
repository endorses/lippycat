//go:build hunter || all

package hunter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractEmailAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "angle brackets standard",
			input: "<user@example.com>",
			want:  "user@example.com",
		},
		{
			name:  "angle brackets with display name",
			input: "\"John Doe\" <john@example.com>",
			want:  "john@example.com",
		},
		{
			name:  "angle brackets with extra spaces",
			input: "  < user@example.com >  ",
			want:  "user@example.com",
		},
		{
			name:  "bare address",
			input: "user@example.com",
			want:  "user@example.com",
		},
		{
			name:  "bare address with trailing params",
			input: "user@example.com SIZE=12345",
			want:  "user@example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "no @ sign",
			input: "invalid",
			want:  "",
		},
		{
			name:  "SMTP MAIL FROM format",
			input: "<alice@example.com> SIZE=1024",
			want:  "alice@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEmailAddress(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsSubjectHeader(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    bool
	}{
		{
			name:    "standard subject header",
			payload: "Subject: Hello World",
			want:    true,
		},
		{
			name:    "lowercase subject",
			payload: "subject: Hello",
			want:    true,
		},
		{
			name:    "mixed case subject",
			payload: "SubJeCT: Test",
			want:    true,
		},
		{
			name:    "not a subject header",
			payload: "From: user@example.com",
			want:    false,
		},
		{
			name:    "subject in middle",
			payload: "Re: Subject matter",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSubjectHeader(tt.payload)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractSubjectLine(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "simple subject",
			payload: "Subject: Hello World",
			want:    "Hello World",
		},
		{
			name:    "subject with leading spaces",
			payload: "Subject:    Hello",
			want:    "Hello",
		},
		{
			name:    "subject with CRLF",
			payload: "Subject: Test\r\nFrom: user@example.com",
			want:    "Test",
		},
		{
			name:    "subject with LF only",
			payload: "Subject: Test\nFrom: user@example.com",
			want:    "Test",
		},
		{
			name:    "empty subject",
			payload: "Subject:",
			want:    "",
		},
		{
			name:    "subject with special chars",
			payload: "Subject: Re: [URGENT] Invoice #12345",
			want:    "Re: [URGENT] Invoice #12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSubjectLine(tt.payload)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractSMTPFields_Commands(t *testing.T) {
	af := &ApplicationFilter{}

	tests := []struct {
		name          string
		payload       []byte
		metadata      map[string]interface{}
		wantSender    string
		wantRecipient string
		wantSubject   string
	}{
		{
			name:       "MAIL FROM command",
			payload:    []byte("MAIL FROM:<sender@example.com>\r\n"),
			wantSender: "sender@example.com",
		},
		{
			name:       "mail from lowercase",
			payload:    []byte("mail from:<sender@test.com>\r\n"),
			wantSender: "sender@test.com",
		},
		{
			name:       "MAIL FROM with SIZE param",
			payload:    []byte("MAIL FROM:<user@example.com> SIZE=12345\r\n"),
			wantSender: "user@example.com",
		},
		{
			name:          "RCPT TO command",
			payload:       []byte("RCPT TO:<recipient@example.com>\r\n"),
			wantRecipient: "recipient@example.com",
		},
		{
			name:          "rcpt to lowercase",
			payload:       []byte("rcpt to:<recipient@test.com>\r\n"),
			wantRecipient: "recipient@test.com",
		},
		{
			name:        "Subject header",
			payload:     []byte("Subject: Important Message\r\n"),
			wantSubject: "Important Message",
		},
		{
			name:    "Using metadata for MAIL",
			payload: []byte("MAIL FROM:<meta@example.com>\r\n"),
			metadata: map[string]interface{}{
				"type":    "command",
				"command": "MAIL FROM",
				"args":    "<metadata@example.com>",
			},
			wantSender: "metadata@example.com",
		},
		{
			name:    "Using metadata for RCPT",
			payload: []byte("RCPT TO:<meta@example.com>\r\n"),
			metadata: map[string]interface{}{
				"type":    "command",
				"command": "RCPT TO",
				"args":    "<recipient-meta@example.com>",
			},
			wantRecipient: "recipient-meta@example.com",
		},
		{
			name:    "EHLO command (no email fields)",
			payload: []byte("EHLO example.com\r\n"),
		},
		{
			name:    "DATA command (no email fields)",
			payload: []byte("DATA\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, recipient, subject := af.extractSMTPFields(tt.payload, tt.metadata)
			assert.Equal(t, tt.wantSender, sender, "sender mismatch")
			assert.Equal(t, tt.wantRecipient, recipient, "recipient mismatch")
			assert.Equal(t, tt.wantSubject, subject, "subject mismatch")
		})
	}
}

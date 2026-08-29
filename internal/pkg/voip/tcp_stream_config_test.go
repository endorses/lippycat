package voip

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTCPStreamUsesInjectedSecurityConfig(t *testing.T) {
	original := GetConfig()
	t.Cleanup(func() { SetConfig(original) })

	injected := *DefaultConfig()
	injected.Security.MaxContentLength = 16
	injected.Security.MaxMessageSize = 1024
	stream := &bufferedSIPStream{
		ctx:     context.Background(),
		factory: &sipStreamFactory{config: &injected},
	}

	global := *DefaultConfig()
	global.Security.MaxContentLength = 1
	global.Security.MaxMessageSize = 1
	SetConfig(&global)

	message := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Call-ID: immutable-config\r\n" +
		"Content-Length: 2\r\n\r\nok"
	got, err := stream.readCompleteSipMessageFromReader(bufio.NewReader(strings.NewReader(message)))
	require.NoError(t, err)
	require.Equal(t, message, string(got))
}

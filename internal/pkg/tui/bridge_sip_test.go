//go:build tui || all

package tui

import (
	"testing"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
)

func TestIsSIPBytesRecognizesSharedRequestMethods(t *testing.T) {
	for _, method := range sharedsip.RequestMethods {
		t.Run(method, func(t *testing.T) {
			if !isSIPBytes([]byte(method + " sip:alice@example.test SIP/2.0\r\n")) {
				t.Fatalf("shared SIP method %s was not detected", method)
			}
		})
	}
}

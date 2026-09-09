package radius

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ValidateNAI enforces RFC 7542 section 2.2 and already-NFC text without
// rewriting identity bytes. Intentional non-NAI bytes use a User-Name AVP.
func ValidateNAI(value string) error {
	invalid := func() error {
		return fmt.Errorf("invalid or non-NFC NAI; use a complete User-Name radiusAttribute AVP for intentional bytes")
	}
	if len(value) == 0 || len(value) > 253 || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return invalid()
	}
	parts := strings.Split(value, "@")
	if len(parts) > 2 {
		return invalid()
	}
	user := parts[0]
	if user != "" {
		for _, atom := range strings.Split(user, ".") {
			if atom == "" {
				return invalid()
			}
			for _, r := range atom {
				if !naiAlphaDigit(r) && r < utf8.RuneSelf && !strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", r) {
					return invalid()
				}
			}
		}
	} else if len(parts) == 1 {
		return invalid()
	}
	if len(parts) == 2 {
		labels := strings.Split(parts[1], ".")
		if len(labels) < 2 {
			return invalid()
		}
		for _, label := range labels {
			if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return invalid()
			}
			for _, r := range label {
				if !naiAlphaDigit(r) && r < utf8.RuneSelf && r != '-' {
					return invalid()
				}
			}
		}
	}
	return nil
}

func naiAlphaDigit(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

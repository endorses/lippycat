package radius

import (
	"encoding/hex"
	"fmt"
)

// PublicAttributes is the routine-output allowlist. Values are hex encoded so
// arbitrary bytes cannot inject terminal control sequences or lose identity.
// Repeated instances retain wire order. Credentials, authenticators, unknown
// attributes and unrecognized vendor subattributes are never exposed.
func PublicAttributes(message *Message) []string {
	result := make([]string, 0)
	if message == nil {
		return result
	}
	for _, a := range message.Attributes {
		switch a.Type {
		case 1, 4, 5, 6, 8, 30, 31, 32, 40, 44, 61, 87, 95:
			result = append(result, fmt.Sprintf("%d:hex:%s", a.Type, hex.EncodeToString(a.Value)))
		case 26:
			if a.VendorID == DSLForumVendorID {
				for _, v := range a.VendorAttributes {
					if v.Type == 1 {
						result = append(result, "26/3561/1:hex:"+hex.EncodeToString(v.Value))
					}
				}
			}
		}
	}
	return result
}

// IdentityString formats the opaque epoch/sequence identity, never the RADIUS Identifier.
func IdentityString(id Identity) string {
	if id.Sequence == 0 {
		return ""
	}
	return fmt.Sprintf("%x:%d", id.Epoch, id.Sequence)
}

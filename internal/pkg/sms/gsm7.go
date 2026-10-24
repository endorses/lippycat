package sms

import "strings"

// TS 23.038 default alphabet. ESC is handled separately from the table.
var gsmAlphabet = []rune("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")

var gsmExtension = map[byte]rune{0x0a: '\f', 0x14: '^', 0x28: '{', 0x29: '}', 0x2f: '\\', 0x3c: '[', 0x3d: '~', 0x3e: ']', 0x40: '|', 0x65: '€'}

func decodeGSM7(b []byte, offset, count int) (string, error) {
	if count < 0 || offset < 0 || offset+count*7 > len(b)*8 {
		return "", ErrIncomplete
	}
	var out strings.Builder
	escape := false
	for i := 0; i < count; i++ {
		bit := offset + i*7
		v := b[bit/8] >> uint(bit%8)
		if bit%8 > 1 {
			v |= b[bit/8+1] << uint(8-bit%8)
		}
		v &= 127
		if escape {
			r, ok := gsmExtension[v]
			if !ok {
				return "", invalid("reserved GSM7 extension")
			}
			out.WriteRune(r)
			escape = false
			continue
		}
		if v == 27 {
			escape = true
			continue
		}
		out.WriteRune(gsmAlphabet[v])
	}
	if escape {
		return "", invalid("truncated GSM7 escape")
	}
	return out.String(), nil
}

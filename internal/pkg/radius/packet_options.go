package radius

import "fmt"

// validateIPv4Options checks every option boundary without interpreting unknown
// option values. End-of-list terminates options; subsequent bytes are padding.
func validateIPv4Options(options []byte) error {
	for len(options) > 0 {
		switch options[0] {
		case 0: // End of option list.
			return nil
		case 1: // No operation.
			options = options[1:]
		default:
			if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
				return fmt.Errorf("IPv4 option boundary: %w", ErrMalformed)
			}
			options = options[int(options[1]):]
		}
	}
	return nil
}

// validateIPv6Options checks the TLVs after the two-byte hop-by-hop or
// destination-options extension prefix. Unknown options remain opaque.
func validateIPv6Options(options []byte) error {
	for len(options) > 0 {
		if options[0] == 0 { // Pad1 has no length byte.
			options = options[1:]
			continue
		}
		if len(options) < 2 || int(options[1])+2 > len(options) {
			return fmt.Errorf("IPv6 option boundary: %w", ErrMalformed)
		}
		options = options[int(options[1])+2:]
	}
	return nil
}

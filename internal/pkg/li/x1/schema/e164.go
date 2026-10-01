package schema

// ValidE164Number reports whether value satisfies the bundled InternationalE164
// contract: one to fifteen ASCII digits, without an international '+' prefix.
func ValidE164Number(value string) bool {
	if len(value) < 1 || len(value) > 15 {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

package mediaadmission

// ShadowSamplingHash selects transient evidence, never packet identity. Its
// byte order and 32-bit arithmetic match bpf/admission.c on both BPF endians.
// Complete bounded frames include every byte, including changing media payload.
func ShadowSamplingHash(domain DomainID, length uint32, frame []byte) uint32 {
	hash := uint32(2166136261)
	for _, word := range [2]uint32{uint32(domain), length} {
		for shift := uint(0); shift < 32; shift += 8 {
			hash = (hash ^ uint32(byte(word>>shift))) * 16777619
		}
	}
	for _, value := range frame {
		hash = (hash ^ uint32(value)) * 16777619
	}
	// Mix high bits into low bits so small intervals also reflect all payload
	// variation rather than just byte parity.
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	return hash ^ (hash >> 16)
}

// ShadowFrameEligible applies the shared sampling rule to a complete bounded
// frame. Oversized, empty and truncated identities cannot enter correlation.
func ShadowFrameEligible(domain DomainID, frame []byte, sampleEvery uint32) bool {
	if sampleEvery == 0 || len(frame) == 0 || len(frame) > ShadowIdentityBytes {
		return false
	}
	return sampleEvery == 1 || ShadowSamplingHash(domain, uint32(len(frame)), frame)%sampleEvery == 0
}

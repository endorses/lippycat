package securestore

// SealedSize returns the exact output size without sealing or reserving key
// usage. It shares Seal's input limits; callers must still handle Seal failures.
func (w *Writer) SealedSize(p Purpose, b Binding, payloadBytes int) (int, error) {
	if w == nil || w.usage == nil || !p.valid() || !b.valid() || b.Store != w.usage.StoreID() || payloadBytes < 0 || payloadBytes > MaxPlaintextBytes-bindingFixedBytes-len(b.Object) {
		return 0, ErrEnvelope
	}
	return fixedHeaderBytes + len(w.usage.key.id) + nonceBytes + bindingFixedBytes + len(b.Object) + payloadBytes + tagBytes, nil
}

package capture

import "github.com/endorses/lippycat/internal/pkg/reassembly"

// Preserve pool accounting through the stream observation wrapper, including
// orphan controls that never create an observedStream.
func (f observedStreamFactory) RecordOrphanControl() {
	if observer, ok := f.factory.(reassembly.StreamPoolObserver); ok {
		observer.RecordOrphanControl()
	}
}

func (f observedStreamFactory) RecordReplacementDrop(bytes uint64) {
	if observer, ok := f.factory.(reassembly.StreamPoolObserver); ok {
		observer.RecordReplacementDrop(bytes)
	}
}

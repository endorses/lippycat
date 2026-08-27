package voip

// Custom errors shared by synchronous call writers and the asynchronous writer
// implementation. Keep these declarations build-tag agnostic: CallInfo is used
// by role-specific builds that do not include async_writer.go.
var (
	ErrWriterStopped        = &AsyncWriterError{"writer pool is stopped"}
	ErrQueueFull            = &AsyncWriterError{"write queue is full"}
	ErrWriteTimeout         = &AsyncWriterError{"write operation timed out"}
	ErrCallNotFound         = &AsyncWriterError{"call not found"}
	ErrInvalidPacketType    = &AsyncWriterError{"invalid packet type"}
	ErrWriterNotInitialized = &AsyncWriterError{"PCAP writer not initialized"}
)

// AsyncWriterError represents errors from the PCAP writer system.
type AsyncWriterError struct {
	Message string
}

func (e *AsyncWriterError) Error() string {
	return e.Message
}

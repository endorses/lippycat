package offline

// CaptureContext retains the original parser domain independently of effective
// packet decoding and logical emission order. Resolution describes ticks per
// second as Base raised to Exponent; TimestampMissing is per physical record.
type CaptureContext struct {
	Format                      CaptureFormat
	ByteOrder                   CaptureByteOrder
	SectionID                   uint32
	InterfaceID                 uint32
	LinkType                    uint32
	Snaplen                     uint32
	TimestampResolutionBase     uint8
	TimestampResolutionExponent uint8
	TimestampOffset             int64
	TimestampMissing            bool
}

type CaptureFormat uint8

const (
	CaptureFormatPCAP CaptureFormat = iota + 1
	CaptureFormatPCAPNG
)

type CaptureByteOrder uint8

const (
	CaptureLittleEndian CaptureByteOrder = iota + 1
	CaptureBigEndian
)

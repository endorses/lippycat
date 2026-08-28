package voip

// PacketType identifies the per-session output stream.
type PacketType int

const (
	PacketTypeSIP PacketType = iota
	PacketTypeRTP
)

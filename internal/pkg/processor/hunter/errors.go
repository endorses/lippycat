package hunter

import "errors"

var (
	// ErrMaxHuntersReached is returned when the maximum number of hunters is reached
	ErrMaxHuntersReached = errors.New("maximum number of hunters reached")
)

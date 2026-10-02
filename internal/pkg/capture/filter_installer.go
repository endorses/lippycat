package capture

import (
	"context"
	"fmt"

	"github.com/google/gopacket/pcap"
)

// FilterInstaller prepares a fresh capture handle with reception disabled until
// Activate. Implementations must discard pre-attachment packets and preserve the
// explicit filter predicate. Prepare must not leave resources behind on error.
// Errors must be safe for diagnostics and must not contain capture expressions.
// Implementations may be called concurrently for interfaces in one generation.
type FilterInstaller interface {
	Prepare(context.Context, *pcap.Handle, string, string) (PreparedFilter, error)
}

// PreparedFilter owns attachment resources, never the libpcap socket descriptor.
// Activate is called only after every interface is prepared. Close follows reader
// shutdown and handle close. Both methods must serialize with concurrent Close.
type PreparedFilter interface {
	Activate() error
	Close() error
}

func captureFilterInstaller(options []CaptureOptions) FilterInstaller {
	if len(options) == 0 {
		return nil
	}
	return options[len(options)-1].FilterInstaller
}

func prepareCaptureFilter(ctx context.Context, handle *pcap.Handle, name, filter string, installer FilterInstaller) (PreparedFilter, error) {
	if installer == nil {
		if err := handle.SetBPFFilter(filter); err != nil {
			// Classic compiler errors can include sensitive selectors.
			return nil, fmt.Errorf("capture filter could not be installed")
		}
		return nil, nil
	}
	attachment, err := installer.Prepare(ctx, handle, name, filter)
	if err != nil {
		return nil, fmt.Errorf("prepare socket admission: %w", err)
	}
	if attachment == nil {
		return nil, fmt.Errorf("socket admission installer returned no attachment")
	}
	return attachment, nil
}

//go:build li

package delivery

import "github.com/endorses/lippycat/internal/pkg/securestore"

// StorageStatus does not acquire any journal or filesystem lock. Counters count
// complete product+checkpoint attempts and individual durable record removals;
// startup repair and offline operations are not runtime mutation counters.
func (j *Journal) StorageStatus() securestore.StorageStatus {
	status := j.telemetry.Snapshot()
	status.AdmissionBlocked = j.readOnly || status.State != "ready"
	if j.readOnly {
		status.PolicyFaultCode = "migration_required"
	}
	return status
}

func (c *Client) JournalStorageStatus() securestore.StorageStatus {
	if c.journal == nil {
		return securestore.StorageStatus{Mode: "disabled", State: "ready"}
	}
	return c.journal.StorageStatus()
}

func (c *Client) X3JournalStorageStatus() securestore.StorageStatus {
	if c.x3Journal == nil {
		return securestore.StorageStatus{Mode: "disabled", State: "ready"}
	}
	return c.x3Journal.StorageStatus()
}

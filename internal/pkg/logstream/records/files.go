package records

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// Files maps privacy-safe file metadata to files.log. Content is never accepted.
func Files(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.FileMetadataEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected file metadata event, got %T", event)
	}
	env := ev.Envelope()
	r, err := logstream.NewRecord("files", env.Timestamp, ev.FileID, env.UID, ev.Source, ev.Depth, ev.Analyzers,
		ev.MIMEType, ev.Filename, ev.Duration, ev.LocalOrigin, ev.IsOrigin, ev.SeenBytes, ev.TotalBytes,
		ev.MissingBytes, ev.OverflowBytes, ev.TimedOut, ev.ParentFileID, ev.MD5, ev.SHA1, ev.SHA256,
		ev.ExtractedPath, env.CommunityID, env.NodeID)
	return r, true, err
}

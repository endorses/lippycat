//go:build !li

package li

import (
	"context"
	"github.com/endorses/lippycat/internal/pkg/events"
)

const InternetMetadataProfile = "internet_metadata"

type MetadataSender interface{}
type MetadataSinkConfig struct {
	Enabled           bool
	Profile           string
	Manager           *Manager
	Sender            MetadataSender
	NFID              string
	AllowFileMetadata bool
}
type MetadataAuditStats struct{ Delivered, Skipped, Rejected uint64 }
type MetadataSink struct{}

func NewMetadataSink(MetadataSinkConfig) (*MetadataSink, error)       { return &MetadataSink{}, nil }
func (*MetadataSink) HandleEvent(context.Context, events.Event) error { return nil }
func (*MetadataSink) Flush(context.Context) error                     { return nil }
func (*MetadataSink) Close(context.Context) error                     { return nil }
func (*MetadataSink) Stats() MetadataAuditStats                       { return MetadataAuditStats{} }

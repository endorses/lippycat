//go:build (processor || tap || all) && !li

package processor

import "github.com/endorses/lippycat/api/gen/management"

func (p *Processor) populateLIStorageStats(_ *management.ProcessorStorageStats) {}

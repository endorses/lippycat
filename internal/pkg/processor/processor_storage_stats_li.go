//go:build (processor || tap || all) && li

package processor

import "github.com/endorses/lippycat/api/gen/management"

func (p *Processor) populateLIStorageStats(dst *management.ProcessorStorageStats) {
	if p.isLIEnabled() {
		dst.LiState = storageStatusProto(p.liManager.AdministrativeStorageStatus())
	}
}

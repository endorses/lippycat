package offline

import (
	"errors"
	"fmt"
)

// ErrAnalysisPending identifies operations which need completed application
// analysis. A normalized base never answers them with false empty metadata.
var ErrAnalysisPending = errors.New("offline application analysis pending")

// CheckQueryReadiness proves a query depends only on available fields before
// any scan or query file is admitted. Unknown predicates are conservative.
func CheckQueryReadiness(revision AnalysisRevision, spec QuerySpec) error {
	if revision == CompletedRevision {
		return nil
	}
	if revision != BaseRevision {
		return fmt.Errorf("unsupported offline analysis revision %d", revision)
	}
	if spec.Expression != nil {
		if err := spec.Expression.Validate(); err != nil {
			return err
		}
		if !spec.Expression.BaseFieldsOnly() {
			return ErrAnalysisPending
		}
		return nil
	}
	if spec.Match != nil {
		return ErrAnalysisPending
	}
	return nil
}

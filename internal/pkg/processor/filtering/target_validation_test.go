package filtering

import (
	"errors"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

type validatingBPFUpdater struct {
	mockBPFUpdater
	candidate     string
	validationErr error
}

func (u *validatingBPFUpdater) ValidateBPFFilter(candidate string) error {
	u.candidate = candidate
	return u.validationErr
}

func TestLocalValidationDoesNotChangeEffectivePolicy(t *testing.T) {
	updater := &validatingBPFUpdater{validationErr: errors.New("sensitive BPF expression")}
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "tcp"})
	target.SetBPFUpdater(updater)
	filter := &management.Filter{Id: "candidate", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.10", Enabled: true}
	require.ErrorIs(t, target.ValidateFilter(filter), ErrFilterInvalid)
	require.Contains(t, updater.candidate, "192.0.2.10")
	require.Zero(t, updater.FilterCount())
	require.Zero(t, target.FilterCount())
	updater.validationErr = nil
	require.NoError(t, target.ValidateFilter(filter))
	require.Zero(t, updater.FilterCount())
	require.Zero(t, target.FilterCount())
}

func TestLocalUnsupportedIPDoesNotBecomeEmptyBPF(t *testing.T) {
	for _, pattern := range []string{"invalid-sensitive-selector", "192.0.2.*", "999.1.2.3/24"} {
		target := NewLocalTarget(LocalTargetConfig{})
		filter := &management.Filter{Id: "candidate", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern, Enabled: true}
		require.ErrorIs(t, target.ValidateFilter(filter), ErrFilterInvalid)
		_, err := target.ApplyFilter(filter)
		require.ErrorIs(t, err, ErrFilterInvalid)
		_, err = target.ApplyFilterBatch([]*management.Filter{filter})
		require.ErrorIs(t, err, ErrFilterInvalid)
		require.Empty(t, target.GetActiveFilters())
	}
}

func TestLocalReconciliationErrorsHideSelectors(t *testing.T) {
	marker := "sensitive-selector-marker"
	for _, coordinator := range []bool{false, true} {
		target := NewLocalTarget(LocalTargetConfig{})
		target.SetBPFUpdater(&mockBPFUpdater{err: errors.New(marker)})
		if coordinator {
			target.SetCoordinator(&recordingLocalFilterCoordinator{err: errors.New(marker)})
		}
		_, err := target.ApplyFilter(&management.Filter{Id: marker, Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
		require.Error(t, err)
		require.NotContains(t, err.Error(), marker)
		require.Empty(t, target.GetActiveFilters())
	}
}

func TestLocalValidationRejectsUnavailableEnabledMatchers(t *testing.T) {
	for _, kind := range []management.FilterType{management.FilterType_FILTER_SIP_USER, management.FilterType_FILTER_PHONE_NUMBER, management.FilterType_FILTER_DNS_DOMAIN} {
		target := NewLocalTarget(LocalTargetConfig{})
		f := &management.Filter{Id: "candidate", Type: kind, Pattern: "example", Enabled: true}
		require.ErrorIs(t, target.ValidateFilter(f), ErrLocalFilterCapability)
		_, err := target.ApplyFilter(f)
		require.ErrorIs(t, err, ErrLocalFilterCapability)
		_, err = target.ApplyFilterBatch([]*management.Filter{f})
		require.ErrorIs(t, err, ErrLocalFilterCapability)
		require.Zero(t, target.FilterCount())
	}
}

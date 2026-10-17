//go:build hunter || tap || all

package voip

import "github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"

// Source policy aliases retain the public runtime API while keeping processor
// source adapters independent of the parent VoIP package.
type SignallingPolicy = capturepolicy.SignallingPolicy
type MediaPolicy = capturepolicy.MediaPolicy
type CapturePolicies = capturepolicy.CapturePolicies
type RemoteCallAssociation = capturepolicy.RemoteCallAssociation
type RemoteMediaResolver = capturepolicy.RemoteMediaResolver

const (
	SignallingMatched = capturepolicy.SignallingMatched
	SignallingAll     = capturepolicy.SignallingAll
	SignallingNone    = capturepolicy.SignallingNone
	MediaLocal        = capturepolicy.MediaLocal
	MediaProcessor    = capturepolicy.MediaProcessor
)

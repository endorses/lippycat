//go:build !race

package voip

// When race detector is disabled, this file is included and sets raceDetectorEnabled to false
const raceDetectorEnabled = false

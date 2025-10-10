//go:build race

package voip

// When race detector is enabled, this file is included and sets raceEnabled to true
const raceDetectorEnabled = true

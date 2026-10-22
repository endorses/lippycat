//go:build (processor || tap || all) && li

package processor

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
)

// Prepare immutable encoder settings before opening stores, listeners or outputs.
// The runtime publishes these encoders only after construction has succeeded.
func (p *Processor) prepareLIWireFormats() error {
	timestamp, err := x2x3.ParseTimestampFormat(p.config.LIDeliveryTimestampFormat)
	if err != nil {
		return fmt.Errorf("invalid LI timestamp format: %w", err)
	}
	matchedTarget, err := li.ParseMatchedTargetFormat(p.config.LIDeliveryMatchedTargetFormat)
	if err != nil {
		return fmt.Errorf("invalid LI matched target format: %w", err)
	}
	sequencer := x2x3.NewSequencer(0)
	x2, err := x2x3.NewX2EncoderWithTimestampFormat(sequencer, "", p.config.ProcessorID, timestamp)
	if err != nil {
		return fmt.Errorf("configure LI X2 timestamp format: %w", err)
	}
	x3, err := x2x3.NewX3EncoderWithTimestampFormat(sequencer, "", p.config.ProcessorID, timestamp)
	if err != nil {
		return fmt.Errorf("configure LI X3 timestamp format: %w", err)
	}
	radius, err := x2x3.NewRADIUSEncoderWithTimestampFormat(sequencer, "", p.config.ProcessorID, p.config.ProcessorID, timestamp)
	if err != nil {
		return fmt.Errorf("configure LI RADIUS timestamp format: %w", err)
	}
	p.liStorage.sequencer, p.liStorage.x2Encoder, p.liStorage.x3Encoder = sequencer, x2, x3
	p.liStorage.radiusEncoder, p.liStorage.matchedTargetFormat = radius, matchedTarget
	return nil
}

// addLIMatchedTarget annotates already admitted single-target product. It never
// performs target matching or changes attribution, direction, or authorization.
func (p *Processor) addLIMatchedTarget(pdu *x2x3.PDU, task *li.InterceptTask) error {
	if task == nil || len(task.Targets) != 1 {
		return nil
	}
	if p.liStorage == nil {
		return fmt.Errorf("LI wire formats are not initialized")
	}
	var value string
	switch p.liStorage.matchedTargetFormat {
	case li.MatchedTargetFormatBare:
		if pdu.Header.PayloadFormat == x2x3.PayloadFormatRADIUS {
			return nil
		}
		value = task.Targets[0].Value
	case li.MatchedTargetFormatTargetIdentifier:
		var err error
		value, err = li.MarshalTargetIdentifier(task.Targets[0])
		if err != nil {
			return fmt.Errorf("encode LI matched target: %w", err)
		}
		if value == "" {
			return nil
		}
	default:
		return fmt.Errorf("LI matched target format is not initialized")
	}
	pdu.AddAttribute(x2x3.NewAttributeBuilder().MatchedTargetIdentifier(value))
	return nil
}

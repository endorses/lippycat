// demo-traffic generates synthetic captures for lippycat screenshots and demos.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var captureStart = time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "demo-traffic:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("demo-traffic", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "testdata/pcaps/demo-mixed.pcap", "destination PCAP (replaced on successful generation)")
	duration := flags.Duration("duration", time.Minute, "capture duration")
	pps := flags.Int("pps", 30, "packets per second in the capture timestamps")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	count, err := writeCapture(ctx, *output, *duration, *pps)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Generated %s: %d synthetic packets, %s at %d packets/s\n", *output, count, *duration, *pps)
	return err
}

func writeCapture(ctx context.Context, destination string, duration time.Duration, pps int) (count int64, err error) {
	if destination == "" {
		return 0, errors.New("output path must not be empty")
	}
	if duration <= 0 {
		return 0, errors.New("duration must be positive")
	}
	// Classic PCAP stores microseconds; keep adjacent records distinguishable.
	if pps <= 0 || pps > 1_000_000 {
		return 0, errors.New("pps must be between 1 and 1000000 (PCAP microsecond precision)")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	packets := int64(duration/time.Second)*int64(pps) +
		(int64(duration%time.Second)*int64(pps)+int64(time.Second)-1)/int64(time.Second)
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return 0, fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".demo-traffic-*.pcap")
	if err != nil {
		return 0, fmt.Errorf("create temporary capture: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close temporary capture: %w", closeErr))
			}
		}
		if removeErr := os.Remove(file.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary capture: %w", removeErr))
		}
	}()
	buffer := bufio.NewWriter(file)
	writer := pcapgo.NewWriter(buffer)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return 0, fmt.Errorf("write capture header: %w", err)
	}
	for cycle := 0; count < packets; cycle++ {
		frames, err := buildCycle(cycle)
		if err != nil {
			return count, fmt.Errorf("build cycle %d: %w", cycle, err)
		}
		if len(frames) == 0 {
			return count, errors.New("traffic cycle contains no packets")
		}
		for _, frame := range frames {
			if count == packets {
				break
			}
			if err := ctx.Err(); err != nil {
				return count, err
			}
			info := gopacket.CaptureInfo{Timestamp: captureStart.Add(packetOffset(count, pps)), CaptureLength: len(frame), Length: len(frame)}
			if err := writer.WritePacket(info, frame); err != nil {
				return count, fmt.Errorf("write packet %d: %w", count, err)
			}
			count++
		}
	}
	if err := buffer.Flush(); err != nil {
		return count, fmt.Errorf("flush capture: %w", err)
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return count, fmt.Errorf("close capture: %w", closeErr)
	}
	if err := os.Rename(file.Name(), destination); err != nil {
		return count, fmt.Errorf("publish capture: %w", err)
	}
	return count, nil
}

func packetOffset(index int64, pps int) time.Duration {
	return time.Duration(index/int64(pps))*time.Second +
		time.Duration(index%int64(pps))*time.Second/time.Duration(pps)
}

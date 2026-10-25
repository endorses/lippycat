//go:build cli || hunter || processor || tap || tui || all

// inspect reads one whitespace-separated hex UDP payload. It is a research tool,
// not a production capture mode or connection tracker.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/endorses/lippycat/experiments/quicinitial"
)

func run() error {
	path := flag.String("hex-file", "", "one UDP payload as hex (required)")
	dcid := flag.String("dcid", "", "original client Initial DCID as hex")
	direction := flag.String("direction", "client", "proven sender direction: client or server")
	headers := flag.Bool("headers-only", false, "inspect v1/v2 shapes without decryption")
	flag.Parse()
	if *path == "" {
		return fmt.Errorf("-hex-file is required")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	const maxInput = 2*quicinitial.MaxDatagramBytes + 8192
	input, readErr := io.ReadAll(io.LimitReader(f, maxInput+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if len(input) > maxInput {
		return fmt.Errorf("hex input exceeds %d bytes", maxInput)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(input)), ""))
	if err != nil {
		return fmt.Errorf("decode UDP hex: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if *headers {
		h, r := quicinitial.Inspect(data)
		return encoder.Encode(struct {
			Headers []quicinitial.Header
			Reason  quicinitial.Reason
		}{h, r})
	}
	if *direction != "client" && *direction != "server" {
		return fmt.Errorf("direction must be client or server")
	}
	id, err := hex.DecodeString(*dcid)
	if err != nil || *dcid == "" {
		return fmt.Errorf("-dcid must contain original Initial DCID hex")
	}
	s, err := quicinitial.NewSession(id)
	if err != nil {
		return err
	}
	defer s.Close()
	d := quicinitial.Client
	if *direction == "server" {
		d = quicinitial.Server
	}
	return encoder.Encode(s.Feed(data, d))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// survey counts supported long-header shapes in a classic PCAP without retaining
// packets or guessing connection keys. It does not perform decryption.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/endorses/lippycat/experiments/quicinitial"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const maxRecordBytes = 128 << 10

type surveyResult struct {
	Packets, UDPDatagrams, SupportedVersionCandidates, ValidLongHeaderDatagrams uint64
	Reasons                                                                     map[quicinitial.Reason]uint64
}

func summarize(input io.Reader) (surveyResult, error) {
	var result surveyResult
	r, err := pcapgo.NewReader(input)
	if err != nil {
		return result, err
	}
	// PCAP snaplen is file-controlled. Clamp BEFORE ReadPacketData can allocate
	// a declared record buffer, while preserving small records in max-snaplen files.
	if r.Snaplen() > maxRecordBytes {
		r.SetSnaplen(maxRecordBytes)
	}
	result.Reasons = make(map[quicinitial.Reason]uint64)
	for {
		data, _, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, err
		}
		result.Packets++
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
		layer := p.Layer(layers.LayerTypeUDP)
		if layer == nil {
			continue
		}
		result.UDPDatagrams++
		udp := layer.(*layers.UDP)
		body := udp.Payload
		if len(body) < 5 || body[0]&0x80 == 0 {
			continue
		}
		version := binary.BigEndian.Uint32(body[1:5])
		if version != quicinitial.Version1 && version != quicinitial.Version2 {
			continue
		}
		result.SupportedVersionCandidates++
		_, reason := quicinitial.Inspect(body)
		result.Reasons[reason]++
		if reason == "" || reason == quicinitial.Retry {
			result.ValidLongHeaderDatagrams++
		}
	}
	return result, nil
}

func run() (err error) {
	flag.Parse()
	if flag.NArg() != 1 {
		return fmt.Errorf("usage: survey capture.pcap")
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	result, err := summarize(f)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

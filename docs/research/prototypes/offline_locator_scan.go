//go:build ignore

// Research-only classic-PCAP locator/core-column scan. This deliberately omits
// normalization, application analysis, full filter metadata, and production
// source-mutation checks. Run from the repository root; see the design report.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type sample struct {
	row, offset int64
	length      uint32
	checksum    uint32
}

func run(path string, width int) (err error) {
	if width != 32 && width != 96 {
		return fmt.Errorf("width must be 32 or 96")
	}
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	index, err := os.CreateTemp("", "lc-locator-prototype-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, index.Close(), os.Remove(index.Name())) }()
	start := time.Now()
	digest := sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(source, digest), 256<<10)
	writer := bufio.NewWriterSize(index, 256<<10)
	var header [24]byte
	if _, err = io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	var order binary.ByteOrder
	var nanos bool
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1":
		order = binary.LittleEndian
	case "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
		nanos = true
	case "\xa1\xb2\xc3\xd4":
		order = binary.BigEndian
	case "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
		nanos = true
	default:
		return fmt.Errorf("prototype supports uncompressed classic PCAP only")
	}
	if width == 96 && order.Uint32(header[20:])&0xffff != 1 {
		return fmt.Errorf("core-column prototype requires Ethernet")
	}
	var eth layers.Ethernet
	var vlan layers.Dot1Q
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &vlan, &ipv4, &ipv6, &tcp, &udp)
	parser.IgnoreUnsupported = true
	decoded := make([]gopacket.LayerType, 0, 8)
	payload := make([]byte, 0, 65536)
	var record [16]byte
	var row [96]byte
	var count, regressions, decodeErrors, capturedBytes, fragments, vxlan, esp uint64
	var previousSec, previousNS uint32
	var samples []sample
	offset := int64(24)
	for {
		_, e := io.ReadFull(reader, record[:])
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		sec, ns := order.Uint32(record[:]), order.Uint32(record[4:])
		captured, original := order.Uint32(record[8:]), order.Uint32(record[12:])
		if (!nanos && ns >= 1000000) || (nanos && ns >= 1000000000) || captured > 16<<20 {
			return fmt.Errorf("invalid record at %d", offset)
		}
		if !nanos {
			ns *= 1000
		}
		if count > 0 && (sec < previousSec || sec == previousSec && ns < previousNS) {
			regressions++
		}
		previousSec, previousNS = sec, ns
		capturedBytes += uint64(captured)
		if int(captured) > cap(payload) {
			payload = make([]byte, captured)
		} else {
			payload = payload[:captured]
		}
		if _, e = io.ReadFull(reader, payload); e != nil {
			return e
		}
		clear(row[:])
		binary.LittleEndian.PutUint64(row[:], uint64(offset+16))
		binary.LittleEndian.PutUint64(row[8:], uint64(sec))
		binary.LittleEndian.PutUint32(row[16:], ns)
		binary.LittleEndian.PutUint32(row[20:], captured)
		binary.LittleEndian.PutUint32(row[24:], original)
		// row[28:32] is the single source-context ID (zero here).
		if width == 96 {
			if e = parser.DecodeLayers(payload, &decoded); e != nil {
				decodeErrors++
			}
			for _, layer := range decoded {
				switch layer {
				case layers.LayerTypeIPv4:
					if ipv4.Flags&layers.IPv4MoreFragments != 0 || ipv4.FragOffset != 0 {
						fragments++
					}
					if ipv4.Protocol == layers.IPProtocolESP {
						esp++
					}
					copy(row[32:48], ipv4.SrcIP)
					copy(row[48:64], ipv4.DstIP)
					row[68] = byte(ipv4.Protocol)
					row[69] = 4
				case layers.LayerTypeIPv6:
					if ipv6.NextHeader == layers.IPProtocolIPv6Fragment {
						fragments++
					}
					if ipv6.NextHeader == layers.IPProtocolESP {
						esp++
					}
					copy(row[32:48], ipv6.SrcIP)
					copy(row[48:64], ipv6.DstIP)
					row[68] = byte(ipv6.NextHeader)
					row[69] = 6
				case layers.LayerTypeTCP:
					binary.LittleEndian.PutUint16(row[64:], uint16(tcp.SrcPort))
					binary.LittleEndian.PutUint16(row[66:], uint16(tcp.DstPort))
					row[70] = 1
				case layers.LayerTypeUDP:
					if udp.DstPort == 4789 {
						vxlan++
					}
					binary.LittleEndian.PutUint16(row[64:], uint16(udp.SrcPort))
					binary.LittleEndian.PutUint16(row[66:], uint16(udp.DstPort))
					row[70] = 1
				}
			}
			// Remaining bytes reserve presence/metadata/string/flow references. Full
			// production metadata is intentionally not computed by this experiment.
		}
		if _, e = writer.Write(row[:width]); e != nil {
			return e
		}
		if count%8192 == 0 && len(samples) < 64 {
			samples = append(samples, sample{int64(count), offset + 16, captured, crc32.ChecksumIEEE(payload)})
		}
		count++
		offset += 16 + int64(captured)
	}
	if err = writer.Flush(); err != nil {
		return err
	}
	if err = index.Sync(); err != nil {
		return err
	}
	elapsed := time.Since(start)
	// Check that sampled random-access locators recover the original bytes.
	for _, s := range samples {
		if _, err = index.ReadAt(row[:width], s.row*int64(width)); err != nil {
			return err
		}
		loc := int64(binary.LittleEndian.Uint64(row[:]))
		length := binary.LittleEndian.Uint32(row[20:])
		if loc != s.offset || length != s.length {
			return fmt.Errorf("locator mismatch")
		}
		data := make([]byte, length)
		if _, err = source.ReadAt(data, loc); err != nil {
			return err
		}
		if crc32.ChecksumIEEE(data) != s.checksum {
			return fmt.Errorf("sample data mismatch")
		}
	}
	fmt.Printf("width=%d packets=%d source_bytes=%d index_bytes=%d regressions=%d decode_errors=%d checked=%d elapsed=%s sha256=%x captured_bytes=%d fragment_candidates=%d vxlan_candidates=%d esp_candidates=%d\n", width, count, offset, count*uint64(width), regressions, decodeErrors, len(samples), elapsed, digest.Sum(nil), capturedBytes, fragments, vxlan, esp)
	return nil
}

func main() {
	path := flag.String("pcap", "", "classic PCAP path")
	width := flag.Int("width", 32, "32-byte locator or 96-byte locator/core row")
	flag.Parse()
	if err := run(*path, *width); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

package capture

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

func StartLiveSniffer(interfaces, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	var devices []pcaptypes.PcapInterface
	for _, device := range strings.Split(interfaces, ",") {
		iface := pcaptypes.CreateLiveInterface(device)
		devices = append(devices, iface)
	}
	startSniffer(devices, filter)
}

func StartOfflineSniffer(readFile, filter string, startSniffer func(devices []pcaptypes.PcapInterface, filter string)) {
	file, err := os.Open(readFile)
	if err != nil {
		log.Fatal("Could not read file.")
	}
	defer file.Close()
	iface := pcaptypes.CreateOfflineInterface(file)
	devices := []pcaptypes.PcapInterface{iface}
	startSniffer(devices, filter)
}

func StartSniffer(devices []pcaptypes.PcapInterface, filter string) {
	fmt.Println("Starting Sniffer")
	streamFactory := NewStreamFactory()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	Init(devices, filter, processPacket, assembler)
}

type streamFactory struct{}

func NewStreamFactory() tcpassembly.StreamFactory {
	return &streamFactory{}
}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processStream(&r)
	return &r
}

func processStream(r io.Reader) {
	for {
		full, err := io.ReadAll(r)
		if err != nil || len(full) == 0 {
			return
		}
	}
}

func processPacket(packetChan <-chan PacketInfo, assembler *tcpassembly.Assembler) {
	for p := range packetChan {
		packet := p.Packet
		switch layer := packet.TransportLayer().(type) {
		case *layers.TCP:
			// fmt.Println("TCP")
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				layer,
				packet.Metadata().Timestamp,
			)
		case *layers.UDP:
			// fmt.Println("UDP")
		}
		fmt.Printf("%s\n", p.Packet)
	}
}

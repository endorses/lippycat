package sniff

import (
	"fmt"
	"io"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/spf13/cobra"
)

var SniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Start lippycat in sniff mode",
	Long:  `Start lippycat in sniff mode. Monitor the specified device`,
	Run:   sniff,
}

var (
	interfaces string
	filter     string
)

func sniff(cmd *cobra.Command, args []string) {
	streamFactory := NewTCPStreamFactory()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	var ifaces []pcaptypes.PcapInterface
	for _, device := range strings.Split(interfaces, ",") {
		iface := pcaptypes.CreateLiveInterface(device)
		ifaces = append(ifaces, iface)
	}
	capture.Init(ifaces, filter, processPacket, assembler)
}

type tcpStreamFactory struct{}

func NewTCPStreamFactory() tcpassembly.StreamFactory {
	return &tcpStreamFactory{}
}

func (f *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go processStream(&r)
	return &r
}

func processStream(r io.Reader) {
}

func processPacket(packetChan <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
	for p := range packetChan {
		// fmt.Printf("[%s] %s\n", p.Device, p.Packet)
		fmt.Printf("%s\n", p.Packet)
	}
}

func init() {
	SniffCmd.AddCommand(voipCmd)
	SniffCmd.Flags().StringVarP(&interfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	SniffCmd.Flags().StringVarP(&filter, "filter", "f", "", "bpf filter to apply")
	// sniffCmd.Flags().BoolVarP("promiscuous", "p", false, "use promiscuous mode")
}

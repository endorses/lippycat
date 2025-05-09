package voip

import (
	"os"
	"time"

	"github.com/google/gopacket"
)

var sipFile, rtpFile *os.File

func CloseWriters() {
	sipFile.Close()
	rtpFile.Close()
}

func WriteSIP(callID string, packet gopacket.Packet) {
	mu.Lock()
	defer mu.Unlock()

	if call, ok := callMap[callID]; ok && call.SIPWriter != nil {
		call.SIPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		call.LastUpdated = time.Now()
	}
}

func WriteRTP(callID string, packet gopacket.Packet) {
	mu.Lock()
	defer mu.Unlock()

	if call, ok := callMap[callID]; ok && call.RTPWriter != nil {
		call.RTPWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		call.LastUpdated = time.Now()
	}
}

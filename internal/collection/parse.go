package collection

import (
	"fmt"

	"github.com/firecracker28/SafeNet/internal/objects"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
Takes in a packet and stores any important
data from various packet layers. Currently just
outputs to screen.
Args: gopacket.Packet packet
*/
func ParsePacket(packet gopacket.Packet) objects.Packet {
	protocols := ""
	var srcPort, destPort string
	var srcIP, destIP string
	timestamp := packet.Metadata().Timestamp.String()
	fmt.Printf("TimeStamp: %v", timestamp)
	packetLength := packet.Metadata().CaptureLength
	fmt.Printf("Length: %v", packetLength)
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		applicationProtocol := applicationLayer.LayerType().String()
		protocols += applicationProtocol + " "
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		protocols += "TCP "
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = tcp.SrcPort.String()
		destPort = tcp.DstPort.String()
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		protocols += "UDP "
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = udp.SrcPort.String()
		destPort = udp.DstPort.String()
	}
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		networkLayerProtocol := networkLayer.LayerType().String()
		protocols += networkLayerProtocol
	}
	ipv4_layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4_layer != nil {
		ip, _ := ipv4_layer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		destIP = ip.DstIP.String()
	}
	p := objects.MakePacket(timestamp, packetLength, protocols, srcPort, destPort, srcIP, destIP)
	return p
}

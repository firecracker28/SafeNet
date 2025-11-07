package collection

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
Takes in a packet and stores any important
data from various packet layers. Currently just
outputs to screen.
Args: gopacket.Packet packet
TODO: Transition to database storage
*/
func ParsePacket(packet gopacket.Packet) {
	timestamp := packet.Metadata().Timestamp
	fmt.Printf("TimeStamp: %v", timestamp)
	packetLength := packet.Metadata().CaptureLength
	fmt.Printf("Length: %v", packetLength)
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		applicationProtocol := applicationLayer.LayerType()
		fmt.Printf("Application Layer Protcol %v", applicationProtocol)
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Print("Transport Layer Protocol: TCP")
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("Src Port: %v", tcp.SrcPort)
		fmt.Printf("Dest Port: %v", tcp.DstPort)
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Print("Transport Layer Protocol: UDP")
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("Src Port: %v", udp.SrcPort)
		fmt.Printf("Dest Port: %v", udp.DstPort)
	}
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		networkLayerProtocol := networkLayer.LayerType()
		fmt.Printf("Network Layer Protocol: %v", networkLayerProtocol)
	}
	ipv4_layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4_layer != nil {
		ip, _ := ipv4_layer.(*layers.IPv4)
		fmt.Printf("Src IP Address: %v", ip.SrcIP)
		fmt.Printf("Dest Port: %v", ip.DstIP)
	}
}

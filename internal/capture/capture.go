package capture

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/*
Takes in a packet and stores any important
data from various packet layers. Currently just
outputs to screen.
Args: gopacket.Packet packet
TODO: Transition to database storage
*/
func displayPacket(packet gopacket.Packet) {
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

/*
Starts live packet capture from predetermined port for a predetermined time.
TODO: Add CLI so port and capture time can be configured
*/
func capturePacket() {
	netinterface := "eth0"
	maxBytes := 1600
	timeout := 30 * time.Second

	if handle, error := pcap.OpenLive(netinterface, int32(maxBytes), true, timeout); error != nil {
		panic(error)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		log.Printf("Error setting filter %v", err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			displayPacket(packet)
		}
	}

}

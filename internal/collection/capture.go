package collection

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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
			ParsePacket(packet)
		}
	}

}

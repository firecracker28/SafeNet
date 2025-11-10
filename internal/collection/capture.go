package collection

import (
	"fmt"
	"log"
	"time"

	"github.com/firecracker28/SafeNet/internal/storage"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

/*
Starts live packet capture from predetermined port for a predetermined time.
TODO: Add CLI so port and capture time can be configured
*/
func CapturePacket() {
	netinterface := "\\Device\\NPF_{E8322E87-2762-4710-A744-5D2A9D7B2BA4}"
	maxBytes := 1600
	timeout := 30 * time.Second
	db := storage.OpenDb()
	fmt.Println("Collecting packets from your network.....")
	if handle, error := pcap.OpenLive(netinterface, int32(maxBytes), true, timeout); error != nil {
		panic(error)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		log.Printf("Error setting filter %v", err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			temp := ParsePacket(packet)
			err := storage.AddPackets(db, temp)
			if err != nil {
				log.Fatal(err)
				panic(err)
			}
		}
	}

}

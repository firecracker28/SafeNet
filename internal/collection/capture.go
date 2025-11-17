package collection

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/firecracker28/SafeNet/internal/storage"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

/*
Starts live packet capture from predetermined port for a predetermined time.
*/
func CapturePackets(device string, maximumBytes int, timeoutLength int, db *sql.DB) {
	netinterface := device
	maxBytes := maximumBytes
	timeout := 0 * time.Second
	if timeoutLength == -1 {
		timeout = pcap.BlockForever
	} else {
		timeout = time.Duration(timeoutLength)
	}
	fmt.Println("Collecting packets from your network.....")
	fmt.Println("PRESS CRTL + C TO STOP PACKET CAPTURE")
	handle, err := pcap.OpenLive(netinterface, int32(maxBytes), true, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	otherErr := handle.SetBPFFilter("ip")
	if otherErr != nil {
		log.Printf("Error setting filter %v", otherErr)
		panic(otherErr)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	// Go routine that stops packet capture when user presses crtl + c
	go func() {
		<-stop
		fmt.Println("Interrupt received, stopping capture...")
		handle.Close() // This will cause packetSource.Packets() to close
	}()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet
	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}
	storage.AddPackets(db, packets)
}

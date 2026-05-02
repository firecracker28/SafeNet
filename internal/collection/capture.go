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
Starts live packet capture from predetermined device interface until users presses CRTL + C.
*/
func CapturePacketsLive(device string, maximumBytes int, timeoutLength int, db *sql.DB, packetFilter string) {
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
	otherErr := handle.SetBPFFilter(packetFilter)
	if otherErr != nil {
		log.Printf("Error setting filter %v", otherErr)
		panic(otherErr)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	// Go routine that stops packet capture when user presses ctrl + c
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

/*
	Captures packet from a given pcap file

Args:
Filepath: Full file path given in file management software
db: database to store packets
*/
func CapturePcap(filepath string, db *sql.DB) {
	handle, err := pcap.OpenOffline(filepath)
	if err != nil {
		log.Fatal("Unable to open pcap file", err)
		//panic(err)
	}
	fmt.Println("Pcap file found....")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet
	fmt.Println("Adding packets")
	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}
	storage.AddPackets(db, packets)
}

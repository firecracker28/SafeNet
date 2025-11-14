package collection

import (
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
func CapturePacket(device string, maximumBytes int, timeoutLength int) {
	netinterface := device
	maxBytes := maximumBytes
	timeout := 0 * time.Second
	if timeoutLength == -1 {
		timeout = pcap.BlockForever
	} else {
		timeout = time.Duration(timeoutLength)
	}
	db := storage.OpenDb()
	defer db.Close()
	fmt.Println("Collecting packets from your network.....")
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
	//Stops packet capture when user presses crtl + c
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Println("Interrupt received, stopping capture...")
		handle.Close() // This will cause packetSource.Packets() to close
	}()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet
	for packet := range packetSource.Packets() {
		fmt.Print(packet)
		packets = append(packets, packet)
	}
	storage.AddPackets(db, packets)
	row := db.QueryRow("SELECT * FROM packets LIMIT 1")
	var ts, proto, srcPort, dstPort, srcIP, dstIP string
	var length, id int
	err = row.Scan(&id, &ts, &length, &proto, &srcPort, &dstPort, &srcIP, &dstIP)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Row: %d %s %d %s %s %s %s %s\n", id, ts, length, proto, srcPort, dstPort, srcIP, dstIP)
	fmt.Println("Finished collecting packets ... Analyzing")
}

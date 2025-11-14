package main

import (
	"flag"
	"fmt"

	//"net"
	//"github.com/google/gopacket/pcap"
	"github.com/firecracker28/SafeNet/internal/collection"
)

func main() {
	device := flag.String("interface", "\\Device\\NPF_{E8322E87-2762-4710-A744-5D2A9D7B2BA4}", " set your WIFI interface")
	maxBytes := flag.Int("maxBytes", 1600, " set maxBytes")
	timeout := flag.Int("timeout", -1, " set timeout")
	flag.Parse()
	intro := "Welcome to SafeNet: Your Network's Security Blanket. REMINDER: Inorder to stop packet capture press ctrl c"
	fmt.Println(intro)
	collection.CapturePacket(*device, *maxBytes, *timeout)
}

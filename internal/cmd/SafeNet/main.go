package main

import (
	"flag"
	"fmt"

	//"net"
	//"github.com/google/gopacket/pcap"
	"github.com/firecracker28/SafeNet/internal/analysis"
	"github.com/firecracker28/SafeNet/internal/collection"
	"github.com/firecracker28/SafeNet/internal/storage"
)

func main() {
	device := flag.String("interface", "\\Device\\NPF_{E8322E87-2762-4710-A744-5D2A9D7B2BA4}", " set your WIFI interface")
	maxBytes := flag.Int("maxBytes", 1600, " set maxBytes")
	timeout := flag.Int("timeout", -1, " set timeout")
	flag.Parse()
	intro := "Welcome to SafeNet: Your Network's Security Blanket. REMINDER: Inorder to stop packet capture use CTRL+C"
	fmt.Println(intro)
	db := storage.OpenDb()
	defer db.Close()
	collection.CapturePackets(*device, *maxBytes, *timeout, db)
	analysis.Top_Source_IPs(db)
	analysis.Top_Dest_IPs(db)
}

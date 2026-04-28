package main

import (
	"flag"
	"fmt"

	"github.com/firecracker28/SafeNet/internal/analysis"
	"github.com/firecracker28/SafeNet/internal/collection"
	"github.com/firecracker28/SafeNet/internal/storage"
)

func main() {
	device := flag.String("interface", "\\Device\\NPF_{10EE81C9-1222-46BB-B6F5-B4F08EF22426}", " set your WIFI interface")
	maxBytes := flag.Int("maxBytes", 1600, " set maxBytes")
	timeout := flag.Int("timeout", -1, " set timeout")
	filter := flag.String("filter", "tcp", "set packet filter")
	flag.Parse()
	intro := "Welcome to SafeNet: Your Network's Security Blanket."
	fmt.Println(intro)
	db := storage.OpenDb()
	defer db.Close()
	collection.CapturePacketsLive(*device, *maxBytes, *timeout, db, *filter)
	analysis.Top_Source_IPs(db)
	analysis.Top_Dest_IPs(db)
	analysis.SuspiciousIPs(db)
	analysis.DetectPortScan(db, "10.117.157.87")
}

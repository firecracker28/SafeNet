package main

import (
	//"fmt"

	//"github.com/google/gopacket/pcap"
	"github.com/firecracker28/SafeNet/internal/collection"
)

func main() {
	//USE IF YOU DON'T KNOW THE NAME OF YOUR DEVICE
	/*devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	/for _, device := range devices {
		fmt.Println("Name:", device.Name)
		fmt.Println("Description:", device.Description)
	}*/
	collection.CapturePacket()
}

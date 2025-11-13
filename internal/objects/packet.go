package objects

type Packet struct {
	Timestamp string `db:"timestamp"`
	Length    int    `db:"length"`
	Protocols string `db:"protocols"`
	SrcPort   string `db:"src_Port"`
	DestPort  string `db:"dest_Port"`
	SrcIP     string `db:"src_IP"`
	DestIP    string `db:"dest_IP"`
}

func MakePacket(timestamp string, length int, protocols string, srcPort string, destPort string, srcIP string, destIP string) Packet {

	return Packet{
		Timestamp: timestamp,
		Length:    length,
		Protocols: protocols,
		SrcPort:   srcPort,
		DestPort:  destPort,
		SrcIP:     srcIP,
		DestIP:    destIP,
	}
}

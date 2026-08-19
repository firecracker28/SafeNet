package analysis

import (
	"database/sql"
	"fmt"
	"log"
	"slices"

	_ "github.com/mattn/go-sqlite3"
)

/*
Searches packet trace for signs of Port Scanning. Assumes BFF filter is set to TCP
Indicators checked: Amount of SYN packets recieved,
Amount of RST packets recieved, Unique destination ports accessed at target IP address.

	Args:
		db: database to query packets
		target_ip: suspected target ip of port scan
*/
func DetectTCPPortScan(db *sql.DB, target_ip string) {

	query := `SELECT dest_Port, dest_IP
	FROM packets`
	flagQuery := `SELECT SYN,RST,dest_IP
	FROM packets`
	var uniquePorts []string
	var synCount int
	var rstCount int
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal("Failed to query destination ports. Error: ", err)
	}
	defer rows.Close()
	for rows.Next() {
		var port string
		var ip string
		rows.Scan(&port, &ip)
		if ip == target_ip {
			if !slices.Contains(uniquePorts, port) {
				uniquePorts = append(uniquePorts, port)
			}
		}
	}
	flagCounts, err := db.Query(flagQuery)
	if err != nil {
		log.Fatal("Unable to pull flags from database. Error: ", err)
	}
	defer flagCounts.Close()
	var syn int
	var rst int
	var dest_IP string
	for flagCounts.Next() {
		flagCounts.Scan(&syn, &rst, &dest_IP)
		if dest_IP == target_ip {
			if syn == 1 {
				synCount += 1
			}
			if rst == 1 {
				rstCount += 1
			}
		}

	}
	fmt.Println("Unique TCP Ports Scanned:", len(uniquePorts))
	fmt.Println("SYN Count:", synCount)
	fmt.Println("RST Count:", rstCount)
}

func DetectLinuxSACKPanic(db *sql.DB, target_ip string) {

}

func DetectUDPFlood(db *sql.DB, target_ip string, baseline_throughput float64) {

}

func DetectUDPScan(db *sql.DB, target_ip string) {
	query := `SELECT dest_Port, dest_IP
	FROM packets`

	var uniquePorts []string

	rows, err := db.Query(query)
	if err != nil {
		log.Fatal("Failed to query destination ports. Error: ", err)
	}
	defer rows.Close()
	for rows.Next() {
		var port string
		var ip string
		rows.Scan(&port, &ip)
		if ip == target_ip {
			if !slices.Contains(uniquePorts, port) {
				uniquePorts = append(uniquePorts, port)
			}
		}
	}
	fmt.Println("Unique UDP Ports Scanned:", len(uniquePorts))
}

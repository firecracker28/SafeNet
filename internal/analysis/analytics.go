package analysis

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"slices"

	_ "github.com/mattn/go-sqlite3"
)

/*
Selects Top 5 source IP's and displays their frequency
Arguments: SQLite3 datbase
*/
func Top_Source_IPs(db *sql.DB) {
	query := `SELECT src_IP, COUNT(*) AS frequency
	FROM packets
	GROUP BY src_IP
	ORDER BY frequency DESC
	LIMIT 5;`

	rows, err := db.Query(query)
	if err != nil {
		fmt.Print("failed to find top IP's")
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var count int
		expression := "([0-9]{1,3}\\.){3}[0-9]{1,3}"
		err := rows.Scan(&ip, &count)
		if err != nil {
			fmt.Print("failed to scan source IP addresses")
		}
		valid, err := regexp.MatchString(expression, ip)
		if err != nil {
			log.Fatal("regex expression failed. Error: ", err)
		}
		if valid == false {
			continue
		}
		fmt.Println("Source IP address: ", ip, " count: ", count)
	}
}

/*
Selects Top 5 destination IP addresses and displays their frequency
Arguments: SQLite3 database
*/
func Top_Dest_IPs(db *sql.DB) {
	query := `SELECT dest_IP, COUNT(*) as frequency
	FROM packets
	GROUP BY dest_IP
	ORDER BY frequency DESC
	LIMIT 5`

	rows, err := db.Query(query)
	if err != nil {
		fmt.Print("failed to find top IP's")
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var count int
		expression := "([0-9]{1,3}\\.){3}[0-9]{1,3}"
		err := rows.Scan(&ip, &count)
		if err != nil {
			log.Fatal("failed to scan destination IP addresses. Err: ", err)
		}
		//Added to fix blank ip address error
		valid, err := regexp.MatchString(expression, ip)
		if err != nil {
			log.Fatal("regex expression failed. Error: ", err)
		}
		if valid == false {
			continue
		}
		fmt.Println("Destination IP address: ", ip, " count: ", count)
	}
}

/*
Calculates mean of IP counts for both source and destination IP's
Args: SQLite database
*/
func mean(db *sql.DB) int {
	querySrc := `SELECT src_IP, COUNT(*) as frequency
	FROM packets
	GROUP BY src_IP
	ORDER BY frequency DESC`

	queryDest := `SELECT dest_IP, COUNT(*) as frequency
	FROM packets
	GROUP BY dest_IP
	ORDER BY frequency DESC`

	var IPs []string
	var sum int
	var uniqueIPs int
	rows, err := db.Query(querySrc)
	if err != nil {
		log.Fatal("database query for Source IP part of mean failed", err)
	}
	defer rows.Close()
	for rows.Next() {
		var src_IP string
		var count int
		err := rows.Scan(&src_IP, &count)
		if err != nil {
			log.Fatal("counting for mean of source IP's failed", err)
		}
		IPs = append(IPs, src_IP)
		sum += count
		uniqueIPs++

	}
	rows1, err1 := db.Query(queryDest)
	if err1 != nil {
		log.Fatal("database query for Dest IP part of mean has failed")
	}
	defer rows1.Close()
	for rows1.Next() {
		var dest_IP string
		var count int
		err := rows1.Scan(&dest_IP, &count)
		if err != nil {
			log.Fatal("counting for mean of dest IP's failed", err)
		}
		if slices.Contains(IPs, dest_IP) {
			IPs = append(IPs, dest_IP)
			uniqueIPs++
		}
		sum += count
	}
	return sum / uniqueIPs
}

/*
If an IP address has sent or recieved a packet it is
marked as suspicious and outputted to the screen
Args: SQLite database
*/
func SuspiciousIPs(db *sql.DB) {
	var suspiciousIPs []string
	std := mean(db) * 3

	querySrc := `SELECT src_IP, COUNT(*) as frequency
	FROM packets
	GROUP BY src_IP
	ORDER BY frequency DESC`

	queryDest := `SELECT dest_IP, COUNT(*) as frequency
	FROM packets
	GROUP BY dest_IP
	ORDER BY frequency DESC`
	rows, err := db.Query(querySrc)
	if err != nil {
		log.Fatal("database query for Source IP part of mean failed", err)
	}
	defer rows.Close()
	for rows.Next() {
		var src_IP string
		var count int
		err := rows.Scan(&src_IP, &count)
		if err != nil {
			log.Fatal("counting for mean of source IP's failed", err)
		}
		if count > std {
			suspiciousIPs = append(suspiciousIPs, src_IP)
			fmt.Print("Suspicous IP: ", src_IP)
		}

	}
	rows1, err1 := db.Query(queryDest)
	if err1 != nil {
		log.Fatal("database query for Dest IP part of mean has failed")
	}
	defer rows1.Close()
	for rows1.Next() {
		var dest_IP string
		var count int
		err := rows1.Scan(&dest_IP, &count)
		if err != nil {
			log.Fatal("counting for mean of dest IP's failed", err)
		}
		if count > std {
			if !slices.Contains(suspiciousIPs, dest_IP) {
				suspiciousIPs = append(suspiciousIPs, dest_IP)
				fmt.Println("Suspicous IP: ", dest_IP)
			}
		}
	}
}

/*
Searches packet trace for signs of Port Scanning

	Signs checked for:
	Amount of SYN packets recieved
	Amount of RST packets recieved
	Unique destination ports accessed at given IP address
	Args:
	db: database to query packets
	target_ip: suspected target ip of port scan
*/
func DetectPortScan(db *sql.DB, target_ip string) {

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
	fmt.Println("Unique Ports:", len(uniquePorts))
	fmt.Println("SYN Count:", synCount)
	fmt.Println("RST Count:", rstCount)
}

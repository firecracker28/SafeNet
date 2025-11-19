package analysis

import (
	"database/sql"
	"fmt"
	"log"
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
		err := rows.Scan(&ip, &count)
		if err != nil {
			fmt.Print("failed to scan source IP addresses")
		}
		fmt.Println("\n Source IP address: ", ip, " count: ", count)
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
		err := rows.Scan(&ip, &count)
		if err != nil {
			fmt.Print("failed to scan destination IP addresses")
		}
		fmt.Println("\n Destination IP address: ", ip, " count: ", count)
	}
}

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

	alertQuery, err := db.Prepare("INSERT INTO alerts ( ip) VALUES (?)")
	if err != nil {
		log.Fatal(err)
	}
	defer alertQuery.Close()
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
			_, err = alertQuery.Exec()
			if err != nil {
				log.Fatal("error adding alert to database")
			}
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
				fmt.Print("Suspicous IP: ", dest_IP)
			}
		}
	}
}

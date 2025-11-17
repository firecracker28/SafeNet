package analysis

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

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

package analysis

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func TopIPs(db *sql.DB) {
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
			fmt.Print("failed to scan ip addresses")
		}
		fmt.Println("\n Src IP address: ", ip, " count: ", count)
	}
}

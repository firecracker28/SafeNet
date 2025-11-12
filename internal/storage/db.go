package storage

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/firecracker28/SafeNet/internal/decoding"
	"github.com/google/gopacket"
	_ "github.com/mattn/go-sqlite3"
)

/*
adds packet and alert table to database
Arguments: db -> SQL database
*/
func addTables(db *sql.DB) error {
	queryPackets := `
	CREATE TABLE IF NOT EXISTS packets(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp STRING,
	length INTEGER,
	protocols STRING,
	src_Port STRING,
	dest_Port STRING,
	src_IP STRING,
	dest_IP STRING
	)`

	//TODO: add table for alerts
	fmt.Println("Adding table to database....")
	_, err := db.Exec(queryPackets)
	fmt.Println("Successfully added table to database...")
	return err

}

/* Opens and test connection to SQLite database */
func OpenDb() *sql.DB {
	db, err := sql.Open("sqlite3", "C:\\Users\\logan\\OneDrive\\Documents\\SafeNet\\internal\\storage\\packets.db")
	if err != nil {
		log.Print(err)
	}

	err = db.Ping()
	if err != nil {
		log.Print(err)
	}
	fmt.Println("Connection to SQL database successful")
	err = addTables(db)
	if err != nil {
		log.Print(err)
	}
	return db
}

func AddPackets(db *sql.DB, packets gopacket.PacketSource) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("beginning error: %w", err)
	}
	addQuery, err := tx.Prepare("INSERT INTO packets (timestamp,length,protocols,src_Port,dest_Port,src_IP,dest_IP)VALUES (?, ?, ?, ?, ?, ?, ?) ")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("preparing error: %w", err)
	}
	defer addQuery.Close()

	for temp := range packets.Packets() {
		fmt.Println("Adding packets to database....")
		packet := decoding.ParsePacket(temp)
		_, err = addQuery.Exec(packet.Timestamp, packet.Length, packet.Protocols, packet.SrcPort, packet.DestPort, packet.SrcIP, packet.DestIP)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("adding error: %w", err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commiting error: %w", err)
	}
	return err
}

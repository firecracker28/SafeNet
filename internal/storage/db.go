package storage

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/firecracker28/SafeNet/internal/objects"
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
	timestamp STRING NOT NULL,
	length INTEGER NOT NULL,
	protocols STRING NOT NULL,
	src_Port STRING,
	dest_Port STRING,
	src_IP STRING NOT NULL,
	dest_IP STRING NOT NULL
	)`

	//TODO: add table for alerts
	fmt.Println("Adding table to database....")
	_, err := db.Exec(queryPackets)
	fmt.Println("Successfully added table to database...")
	return err

}

/* Opens and test connection to SQLite database */
func OpenDb() *sql.DB {
	db, err := sql.Open("sqlite3", "./internal/storage/packets.db")
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	fmt.Println("Connection to SQL database successful")
	err = addTables(db)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	return db
}

func AddPackets(db *sql.DB, packet objects.Packet) error {
	addQuery, err := db.Prepare("INSERT INTO packets (timestamp,length,protocols,src_Port,dest_Port,src_IP,dest_IP)VALUES (?, ?, ?, ?, ?, ?, ?) ")
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	defer addQuery.Close()
	fmt.Println("Adding packets to database....")
	_, err = addQuery.Exec(packet.Timestamp, packet.Length, packet.Protocols, packet.SrcPort, packet.DestPort)
	return err
}

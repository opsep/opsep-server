package main

import (
	"database/sql"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// DB global to pass around
var DB *sqlx.DB

type APICallLog struct {
	ID                    int       `db:"id" json:"id"`
	CreatedAt             time.Time `db:"created_at" json:"created_at"`
	RequestSha256Digest   string    `db:"request_sha256digest" json:"-"`
	RequestIPAddress      string    `db:"request_ip_address" json:"request_ip_address"`
	RequestUserAgent      string    `db:"request_user_agent" json:"request_user_agent"`
	ResponseDSha256Digest string    `db:"response_dsha256digest" json:"-"`
}

func executeQuery(db *sqlx.DB, query string) (sql.Result, error) {
	statement, err := db.Prepare(query)
	if err != nil {
		return nil, err
	}
	return statement.Exec()
}

func createTables(db *sqlx.DB) {
	log.Println("Creating api_calls table (if it doesn't already exist)...")

	// Create table
	query := `
	CREATE TABLE IF NOT EXISTS api_calls (
		id INTEGER PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
		request_sha256digest VARCHAR(256) NOT NULL,
		request_ip_address VARCHAR(256),
		request_user_agent VARCHAR(256),
		response_dsha256digest VARCHAR(256) NOT NULL
	);`
	_, err := executeQuery(db, query)
	HandleErr(err)

	// Indices
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_request_sha256digest ON api_calls (request_sha256digest);")
	HandleErr(err)
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_request_ip_address ON api_calls (request_ip_address);")
	HandleErr(err)
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_request_user_agent ON api_calls (request_user_agent);")
	HandleErr(err)
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_response_dsha256digest ON api_calls (response_dsha256digest);")
	HandleErr(err)

}

func LogAPICall(db *sqlx.DB, apiCall APICallLog) (sql.Result, error) {
	statement, err := db.Prepare("INSERT INTO api_calls (request_sha256digest, request_ip_address, request_user_agent, response_dsha256digest) VALUES (?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	return statement.Exec(apiCall.RequestSha256Digest, apiCall.RequestIPAddress, apiCall.RequestUserAgent, apiCall.ResponseDSha256Digest)

}

func FetchDecryptionRecord(requestDSha256 string) ([]APICallLog, error) {
	rows, err := DB.Queryx("SELECT id, created_at, request_ip_address, request_user_agent FROM api_calls WHERE request_sha256digest = ? ORDER BY id", requestDSha256)
	if err != nil {
		return []APICallLog{}, err
	}

	// https://stackoverflow.com/questions/17265463/how-do-i-convert-a-database-row-into-a-struct
	results := []APICallLog{}
	for rows.Next() {
		var a APICallLog
		// err = rows.Scan(&r.id, &r.createdAt, &r.requestIPAddress, &r.requestUserAgent)
		err := rows.StructScan(&a)
		log.Println("row", a)
		if err != nil {
			return []APICallLog{}, err
		}
		results = append(results, a)
	}

	return results, nil
}

// InitDB to be called in main and be gloablly accessible in say views
func InitDB() {
	var err error

	DB, err = sqlx.Open("sqlite3", CFG.SQLiteFilePath)
	HandleErr(err)

	createTables(DB)

	err = DB.Ping()
	log.Println("Pinging database...")
	HandleErr(err)

	// TODO: defer close?

}

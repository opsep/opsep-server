package main

import (
	"database/sql"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/guregu/null.v3"
)

// DB global to pass around
var DB *sqlx.DB

type APICallLog struct {
	ServerLogID           int         `db:"id"`
	CreatedAt             time.Time   `db:"created_at"`
	RequestSha256Digest   string      `db:"request_sha256digest"`
	RequestIPAddress      string      `db:"request_ip_address"`
	RequestUserAgent      string      `db:"request_user_agent"`
	ResponseDSha256Digest string      `db:"response_dsha256digest" json:"-"` // Not default surfaced for security (badly generated client plaintext could be brute-forced if leaked)
	ClientRecordID        null.String `db:"client_record_id"`
	DeprecateAt           null.Time   `db:"deprecate_at"`
	RiskMultiplier        null.Int    `db:"risk_multiplier"`
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
		request_ip_address VARCHAR(256) NOT NULL,
		request_user_agent VARCHAR(256) NOT NULL,
		response_dsha256digest VARCHAR(256) NOT NULL,
		-- optional fields
		deprecate_at DATETIME,
		client_record_id VARCHAR(256),
		risk_multiplier SMALLINT
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
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_deprecate_at ON api_calls (deprecate_at);")
	HandleErr(err)
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_client_record_id ON api_calls (client_record_id);")
	HandleErr(err)
	_, err = executeQuery(db, "CREATE INDEX IF NOT EXISTS idx_risk_multiplier ON api_calls (risk_multiplier);")
	HandleErr(err)

}

func LogAPICall(db *sqlx.DB, apiCall APICallLog) (sql.Result, error) {
	query := `INSERT INTO api_calls (request_sha256digest, request_ip_address, request_user_agent, response_dsha256digest, deprecate_at, client_record_id, risk_multiplier) VALUES (:request_sha256digest, :request_ip_address, :request_user_agent, :response_dsha256digest, :deprecate_at, :client_record_id, :risk_multiplier)`
	return db.NamedExec(query, apiCall)

}

func FetchDecryptionRecord(requestDSha256 string) ([]APICallLog, error) {
	rows, err := DB.Queryx("SELECT id, created_at, request_sha256digest, request_ip_address, request_user_agent, risk_multiplier FROM api_calls WHERE request_sha256digest = ? ORDER BY id", requestDSha256)
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

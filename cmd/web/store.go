package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// DB global to pass around
var DB *sql.DB

func HandleErr(e error) {
	if e != nil {
		panic(e)
	}
}

type APICallLog struct {
	token_sha256digest     string
	request_sha256digest   string
	request_ip_address     string
	request_user_agent     string
	response_dsha256digest string
}

func createTables(db *sql.DB) (sql.Result, error) {
	log.Println("Creating table (if it doesn't exist)...")

	statement, err := db.Prepare(`
CREATE TABLE IF NOT EXISTS api_calls (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    token_sha256digest VARCHAR(256) NOT NULL,
    request_sha256digest VARCHAR(256) NOT NULL,
    request_ip_address VARCHAR(256),
    request_user_agent VARCHAR(256),
    response_dsha256digest VARCHAR(256) NOT NULL
);
CREATE INDEX idx_token_sha256digest ON api_calls (token_sha256digest);
CREATE INDEX idx_request_sha256digest ON api_calls (request_sha256digest);
CREATE INDEX idx_request_ip_address ON api_calls (request_ip_address);
CREATE INDEX idx_request_user_agent ON api_calls (request_user_agent);
CREATE INDEX idx_response_dsha256digest ON api_calls (response_dsha256digest);
    `)
	if err != nil {
		return nil, err
	}

	return statement.Exec()
}

func LogAPICall(db *sql.DB, apiCall APICallLog) (sql.Result, error) {
	statement, err := db.Prepare("INSERT INTO api_calls (token_sha256digest, request_sha256digest, request_ip_address, request_user_agent, response_dsha256digest) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	return statement.Exec(apiCall.token_sha256digest, apiCall.request_sha256digest, apiCall.request_ip_address, apiCall.request_user_agent, apiCall.response_dsha256digest)

}

// InitDB to be called in main and be gloablly accessible in say views
func InitDB() {
	var err error

	DB, err = sql.Open("sqlite3", CFG.SQLiteFilePath)
	HandleErr(err)

	_, err = createTables(DB)
	HandleErr(err)

	err = DB.Ping()
	log.Println("Pinging database...")
	HandleErr(err)

	// TODO: defer close?

}

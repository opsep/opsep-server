package main

import (
	"database/sql"
	"fmt"
	"strconv"
)

// DB global to pass around
var DB *sql.DB

func HandleErr(e error) {
	if e != nil {
		panic(e)
	}
}

func createTables(db *sql.DB) (sql.Result, error) {
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

	// FIXME: make this configurable
	DB, err = sql.Open("sqlite3", "./opsep.db")
	HandleErr(err)

	_, err = createTables(DB)
	HandleErr(err)

	// FIXME: delete this
	_, err = LogAPICall(DB,
		APICallLog{
			token_sha256digest:     "xxx",
			request_sha256digest:   "qwer",
			request_ip_address:     "1.1.1.1",
			request_user_agent:     "python",
			response_dsha256digest: "asdf",
		},
	)
	HandleErr(err)
	fmt.Println("inserted")

	// FIXME: add proper ping of DB check here
	/*
		log.Println("Pinging DB for health check...")
		pingErr := conn.Ping()
		if pingErr != nil {
			log.Fatal(pingErr)
		}
		log.Println("Ping success!")
	*/

	// FIXME: delete this
	rows, err := DB.Query("SELECT id FROM api_calls")
	HandleErr(err)
	var id int
	for rows.Next() {
		rows.Scan(&id)
		fmt.Println(strconv.Itoa(id))
	}

	fmt.Println("Done")

	// TODO: defer close?

}

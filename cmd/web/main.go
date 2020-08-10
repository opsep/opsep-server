package main

import (
	"database/sql"
	"fmt"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	_ "github.com/mattn/go-sqlite3"
)

func handleErr(e error) {
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

func logAPICall(db *sql.DB, apiCall APICallLog) (sql.Result, error) {
	statement, err := db.Prepare("INSERT INTO api_calls (token_sha256digest, request_sha256digest, request_ip_address, request_user_agent, response_dsha256digest) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	return statement.Exec(apiCall.token_sha256digest, apiCall.request_sha256digest, apiCall.request_ip_address, apiCall.request_user_agent, apiCall.response_dsha256digest)

}

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Debug route
	e.GET("/ping", PingHandler)

	// Real route
	e.POST("/api/v1/decrypt", DecryptDataHandler)

	db, err := sql.Open("sqlite3", "./opsep.db")
	handleErr(err)

	_, err = createTables(db)
	handleErr(err)

	// FIXME: add ping of DB check here

	_, err = logAPICall(db,
		APICallLog{
			token_sha256digest:     "xxx",
			request_sha256digest:   "qwer",
			request_ip_address:     "1.1.1.1",
			request_user_agent:     "python",
			response_dsha256digest: "asdf",
		},
	)
	handleErr(err)
	fmt.Println("inserted")

	rows, err := db.Query("SELECT id FROM api_calls")
	handleErr(err)
	var id int
	for rows.Next() {
		rows.Scan(&id)
		fmt.Println(strconv.Itoa(id))
	}

	fmt.Println("Done")

	// FIXME: don't hardcode the port:
	e.Logger.Fatal(e.Start(":" + "8080"))
}

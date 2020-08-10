package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	_ "github.com/mattn/go-sqlite3"
)

type APICallLog struct {
	token_sha256digest     string
	request_sha256digest   string
	request_ip_address     string
	request_user_agent     string
	response_dsha256digest string
}

func main() {
	InitDB()

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Debug route
	e.GET("/ping", PingHandler)

	// Real route
	e.POST("/api/v1/decrypt", DecryptDataHandler)

	// FIXME: don't hardcode the port:
	e.Logger.Fatal(e.Start(":" + "8080"))
}

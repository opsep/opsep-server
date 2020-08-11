package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	InitConfig()
	InitDB()

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Debug route
	e.GET("/", StatusHandler)

	// Real route
	e.POST("/api/v1/decrypt", DecryptDataHandler)
	e.GET("/api/v1/logs/:request_dsha256", DecryptRequestLogHandler)

	e.Logger.Fatal(e.Start(CFG.ServerHost + ":" + CFG.ServerPort))
}

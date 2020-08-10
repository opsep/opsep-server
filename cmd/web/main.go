package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

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

	// TODO: allow changing port via settings/CLI:
	e.Logger.Fatal(e.Start(":" + "8080"))
}

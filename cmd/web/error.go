package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

type APIErrorResponse struct {
	ErrName string `json:"error_name"`
	ErrDesc string `json:"error_description"`
}

func HandleAPIError(c echo.Context, e error, apiErr APIErrorResponse) error {
	log.Println("HandleApiError", e, apiErr)
	// FIXME: update httpstatus
	return c.JSON(http.StatusBadRequest, apiErr)
}

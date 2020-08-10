package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

func PingHandler(c echo.Context) error {
	log.Println("Hello PingHandler!")
	return c.String(http.StatusOK, "Pong")
}

// Real API Call starts here

type decryptRequest struct {
	CipherText   string `json:"key_retrieval_ciphertext"`
	TriggerLimit bool   `json:"over_limit"`
}

type decryptResponse struct {
	Plaintext     string `json:"key_recovered"`
	PayloadSha256 string `json:"request_sha256"`
	// RecoveredKeyDSha256 string `json:"decrypted_dsha256"`
	RLLimit     int `json:"ratelimit_limit"`
	RLRemaining int `json:"ratelimit_remaining"`
	RLReset     int `json:"ratelimit_resets_in"`
}

func DecryptDataHandler(c echo.Context) error {
	log.Println("DecryptDataHandler hit")

	request := new(decryptRequest)
	err := c.Bind(request)
	if err != nil {
		return err
	}

	cipherTextBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.CipherText))
	if err != nil {
		log.Println("Ciphertext", request.CipherText)
		return HandleAPIError(c, err, APIErrorResponse{
			ErrName: "B64Decode",
			ErrDesc: "Cannot base64 decode key_retrieval_ciphertext"},
		)
	}
	if len(cipherTextBytes) != 512 {
		log.Println("cipherTextBytes", cipherTextBytes)
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "InvalidLengthCiphertext",
			ErrDesc: "base64 decoded key_retrieval_ciphertext is not 512 bytes",
		})
	}

	requestSha256digest := SingleSHA256(string(cipherTextBytes))
	log.Println("requestDigest", requestSha256digest)

	if request.TriggerLimit == true || AllowThisDecryption() == false {
		// TODO: ping out to notify!

		toReturn := decryptResponse{
			// Do not decrypt
			Plaintext: "", // "" s the nil value for a string field

			// This is fine to return
			PayloadSha256: requestSha256digest,

			// Limit per window
			RLLimit: GlobalLimiter.DecryptsAllowedPerPeriod,
			// Remaining per window
			RLRemaining: 0,
			// Time (in s) until window resets
			RLReset: GlobalLimiter.secondsToExpiry(),
		}

		log.Println("Returning 429...")
		return c.JSON(http.StatusTooManyRequests, toReturn)
	}

	// Perform decryption
	plaintextBytes, err := OAEP256AsymmetricDecrypt(
		cipherTextBytes,
		CFG.RSAPrivKey,
	)
	log.Println("Performed")
	if err != nil {
		return HandleAPIError(c, err, APIErrorResponse{
			ErrName: "DecryptionFail",
			ErrDesc: err.Error(),
		})
	}

	fmt.Println("length plaintextBytes", len(plaintextBytes))
	responseDSHA256DigestHex := DSha256Hex(string(plaintextBytes))
	log.Println("responseDigest", responseDSHA256DigestHex)

	var dat map[string]interface{}

	if err := json.Unmarshal(plaintextBytes, &dat); err != nil {
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "InvalidJSONError",
			ErrDesc: err.Error() + string(plaintextBytes),
		})
	}

	// Extract key from decrypted payload
	key_to_return, exists := dat["key"]
	if exists == false {
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "JSONMissingKeyError",
			ErrDesc: "Decrypted payload JSON lacks `key` attribute.",
		})
	}
	key_str_to_return, ok := key_to_return.(string)
	if ok == false {
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "JSONKeyStringError",
			ErrDesc: "Decrypted payload JSON `key` is invalid string.",
		})
	}

	// Extract deprecate_at from decrypted payload
	deprecate_at, exists := dat["deprecate_at"]
	if exists == true {

		deprecate_at_str, ok := deprecate_at.(string)
		if ok == false {
			return HandleAPIError(c, nil, APIErrorResponse{
				ErrName: "DeprecatedAtFormatError",
				ErrDesc: "Key deprecation time not valid (not string).",
			})
		}

		deprecate_at_t, err := time.Parse(time.RFC3339, deprecate_at_str)
		if err != nil {
			return HandleAPIError(c, nil, APIErrorResponse{
				ErrName: "InvalidTimeError",
				ErrDesc: "Key deprecation time format not valid (cannot parse)",
			})
		}
		if time.Now().After(deprecate_at_t) == true {
			return HandleAPIError(c, nil, APIErrorResponse{
				ErrName: "DeprecatedDecryptionKeyError",
				ErrDesc: "Key to decrypt this payload marked as deprecated.",
			})

		}
	}

	// Log this
	// TODO: move to goroutine/queue for performance
	log.Println("Logging to DB...")
	APICallLog, err := LogAPICall(DB, APICallLog{
		request_sha256digest:   requestSha256digest,
		request_ip_address:     c.RealIP(),
		request_user_agent:     c.Request().UserAgent(),
		response_dsha256digest: responseDSHA256DigestHex,
	})
	if err != nil {
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "DecryptionLoggingError",
			ErrDesc: "Error Logging Decryption Request",
		})
	}
	log.Println("APICallLog created", APICallLog)

	toReturn := decryptResponse{
		Plaintext:     key_str_to_return,
		PayloadSha256: requestSha256digest,
		// Limit per window
		RLLimit: GlobalLimiter.DecryptsAllowedPerPeriod,
		// Remaining per window
		RLRemaining: GlobalLimiter.callsRemaining(),
		// Time (in s) until window resets
		RLReset: GlobalLimiter.secondsToExpiry(),
	}

	return c.JSON(http.StatusOK, toReturn)
}

func DecryptRequestLogHandler(c echo.Context) error {

	requestDSha256 := c.Param("request_dsha256")
	log.Println("requestDSha256", requestDSha256)

	result, err := FetchAPICallRecord(requestDSha256)
	if err != nil {
		log.Println("err", err)
		return err
	}

	log.Println("result", result)
	return c.JSON(http.StatusOK, result)

}

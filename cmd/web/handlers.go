package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func PingHandler(c echo.Context) error {
	log.Println("Hello PingHandler!")
	return c.String(http.StatusOK, "Ping")
}

// Real API Call starts here

type decryptRequest struct {
	// TODO: validate
	Token        string `json:"api_token"`
	CipherText   string `json:"asymmetric_ciphertext_b64"`
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
		// FIXME
		return err
	}

	if request.Token == "" {
		return c.String(http.StatusOK, "FOO") // FIXME
	}

	// FIXME: validate the API token

	cipherTextBytes, err := base64.StdEncoding.DecodeString(request.CipherText)
	if err != nil {
		return HandleAPIError(c, err, APIErrorResponse{
			ErrName: "B64Decode",
			ErrDesc: "Cannot base64 decode asymmetric_ciphertext_b64"},
		)
	}
	if len(cipherTextBytes) != 512 {
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "InvalidLengthCiphertext",
			ErrDesc: "base64 decoded asymmetric_ciphertext_b64 is not 512 bytes",
		})
	}

	requestSha256digest := SingleSHA256(string(cipherTextBytes))
	log.Println("requestDigest", requestSha256digest)

	// FIXME: check and enforce rate limiting!
	limiter := getLimiter(request.Token)
	// "" s the nil value for a string field
	if request.TriggerLimit == true || limiter.incrementLimiter() == false {
		// TODO: ping out to notify!

		toReturn := decryptResponse{
			// Do not decrypt
			Plaintext: "",

			// This is fine to return
			PayloadSha256: requestSha256digest,

			// Limit per window
			RLLimit: limiter.DecryptsAllowedPerPeriod,
			// Remaining per window
			RLRemaining: 0,
			// Time (in s) until window resets
			RLReset: limiter.secondsToExpiry(),
		}

		log.Println("Returning 429...")
		return c.JSON(http.StatusTooManyRequests, toReturn)
	}

	// FIXME: insecure!
	// FIXME: only works for 1 privkey!
	rsaPrivKeyPEM, err := ioutil.ReadFile("insecurepriv.pem")
	if err != nil {
		panic(err) // FIXME
	}

	// log.Println("rsaPrivKeyPEM", rsaPrivKeyPEM)

	// Perform decryption
	plaintextBytes, err := OAEP256AsymmetricDecrypt(
		cipherTextBytes,
		rsaPrivKeyPEM,
	)
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

	// FIXME: disable this (insecure)
	fmt.Println(dat)

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
	//
	// FIXME
	// FIXME
	// FIXME
	//
	// (TODO: move to go routine/queue)
	/*
		APICallLog, err := store.DB.CreateAPICallLog(context.Background(), postgres.CreateAPICallLogParams{
			TokenID:               AToken.ID,
			Action:                2, // Decrypt
			RequestSha256digest:   requestSha256digest,
			RequestIpAddress:      sql.NullString{String: c.RealIP(), Valid: true},
			ResponseDsha256digest: responseDSHA256DigestHex,
		})
		if err != nil {
			return HandleAPIError(c, nil, APIErrorResponse{
				ErrName: "DecryptionLoggingError",
				ErrDesc: "Error Logging Decryption Request",
			})
		}
		log.Println("APICallLog created", APICallLog)

	*/

	toReturn := decryptResponse{
		Plaintext:     key_str_to_return,
		PayloadSha256: requestSha256digest,
		// Limit per window
		RLLimit: limiter.DecryptsAllowedPerPeriod,
		// Remaining per window
		RLRemaining: limiter.callsRemaining(),
		// Time (in s) until window resets
		RLReset: limiter.secondsToExpiry(),
	}

	return c.JSON(http.StatusOK, toReturn)
}

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
		return err
	}

	// FIXME: validate the API token (perhaps allow no API token though)
	if request.Token == "" {
		return c.String(http.StatusOK, "FOO") // FIXME
	}

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

	// TODO: check preset rate-limit and enforce it!
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

	// FIXME: insecure, move to environment variable. Also, store on init of app.
	rsaPrivKeyPEM, err := ioutil.ReadFile("insecurepriv.pem")
	if err != nil {
		return HandleAPIError(c, err, APIErrorResponse{
			ErrName: "MissingPrivateKEK",
			ErrDesc: "Key Encryption Key for decrypting data not found",
		})
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
	// TODO: move to go routine/queue
	log.Println("Logging to DB...")
	APICallLog, err := LogAPICall(DB, APICallLog{
		token_sha256digest:     DSha256Hex(string(request.Token)),
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
		RLLimit: limiter.DecryptsAllowedPerPeriod,
		// Remaining per window
		RLRemaining: limiter.callsRemaining(),
		// Time (in s) until window resets
		RLReset: limiter.secondsToExpiry(),
	}

	return c.JSON(http.StatusOK, toReturn)
}

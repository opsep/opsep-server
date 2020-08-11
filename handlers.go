package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"gopkg.in/guregu/null.v3"
)

func StatusHandler(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, CFG, "  ")
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

	log.Println("length plaintextBytes", len(plaintextBytes))

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
	deprecateAtToInsert := null.NewTime(time.Time{}, false)
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
			return HandleAPIError(c, err, APIErrorResponse{
				ErrName: "InvalidTimeError",
				ErrDesc: "Key deprecation time format not valid (cannot parse)",
			})
		}
		if time.Now().After(deprecate_at_t) == true {
			// TODO: add some sort of admin notification of expired keys
			return HandleAPIError(c, nil, APIErrorResponse{
				ErrName: "DeprecatedDecryptionKeyError",
				ErrDesc: "Key to decrypt this payload marked as deprecated.",
			})
		}
		deprecateAtToInsert = null.NewTime(deprecate_at_t, true)
	}

	// Extract client_record_id from decrypted payload
	clientRecordToInsert := null.NewString("", false)
	clientRecordID, exists := dat["client_record_id"]
	if exists == true {
		// a little confusing, but this must be a string (unknown if client is using INTs or UUIDs)
		clientRecordIDstr, ok := clientRecordID.(string)
		if ok == false {
			return HandleAPIError(c, nil, APIErrorResponse{
				ErrName: "ClientRecordIDFormatError",
				ErrDesc: "client_record_id must be a string",
			})
		}
		clientRecordToInsert = null.NewString(clientRecordIDstr, true)
	}

	// Log this
	// TODO: move to goroutine/queue for performance
	log.Println("Logging to DB...")
	APICallLog, err := LogAPICall(APICallLog{
		RequestSha256Digest:   requestSha256digest,
		RequestIPAddress:      c.RealIP(),
		RequestUserAgent:      c.Request().UserAgent(),
		ResponseDSha256Digest: DSha256Hex(string(plaintextBytes)),
		ClientRecordID:        clientRecordToInsert,
		DeprecateAt:           deprecateAtToInsert,
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

	result, err := FetchDecryptionRecords(requestDSha256)
	if err != nil {
		return HandleAPIError(c, nil, APIErrorResponse{
			ErrName: "FetchDecryptionRecordsError",
			ErrDesc: err.Error(),
		})
	}

	log.Println("result", result)
	return c.JSON(http.StatusOK, result)

}

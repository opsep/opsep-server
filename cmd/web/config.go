package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// TODO: using Prod defaults (except for secure stuff hidden in credentials.yaml)
	SQLiteFilePath           string `json`
	SeverHost                string `json`
	ServerPort               string `json`
	RSAPrivateKeyBytes       []byte `json:"-"`
	DecryptsAllowedPerPeriod int    `json`
	PeriodInSeconds          int    `json`
}

// CFG is an exportable single source of truth for config info & secrets
var CFG *Config

func defaultRead(envVar string, defaultVal string) (toSet string) {
	envVal := os.Getenv(envVar)
	if envVal == "" {
		return defaultVal
	}
	return envVal
}

func InitConfig() {
	log.Println("Generating configs...")

	RSAPrivateKeyString := strings.TrimSpace(os.Getenv("RSA_PRIVATE_KEY"))
	goodRSAPrefix := strings.HasPrefix(RSAPrivateKeyString, "-----BEGIN RSA PRIVATE KEY-----") == true
	goodRSASuffix := strings.HasSuffix(RSAPrivateKeyString, "-----END RSA PRIVATE KEY-----") == true

	if !goodRSAPrefix || !goodRSASuffix {
		panic("RSA Private Key Invalid")
	}

	decryptsPerPeriodStr := defaultRead("DECRYPTS_PER_PERIOD", "100")
	decryptsPerPeriodInt, err := strconv.Atoi(decryptsPerPeriodStr)
	if err != nil {
		log.Println("Invalid DECRYPTS_PER_PERIOD", decryptsPerPeriodStr)
		panic(err)
	}

	periodInSecondsStr := defaultRead("PERIOD_IN_SECONDS", "600")
	periodInSecondsInt, err := strconv.Atoi(periodInSecondsStr)
	if err != nil {
		log.Println("Invalid PERIOD_IN_SECONDS", periodInSecondsStr)
		panic(err)
	}

	cfg := Config{
		SQLiteFilePath:           defaultRead("SQLITE_FILEPATH", "opsep.db"),
		SeverHost:                defaultRead("SERVER_HOST", "localhost"),
		ServerPort:               defaultRead("SERVER_PORT", "80"),
		RSAPrivateKeyBytes:       []byte(RSAPrivateKeyString),
		DecryptsAllowedPerPeriod: decryptsPerPeriodInt,
		PeriodInSeconds:          periodInSecondsInt,
	}

	// FIXME: insecure
	b, err := json.Marshal(cfg)
	HandleErr(err)
	log.Println(string(b))

	CFG = &cfg
}

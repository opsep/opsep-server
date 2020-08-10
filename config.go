package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	SQLiteFilePath           string          `json`
	SeverHost                string          `json`
	ServerPort               string          `json`
	RSAPrivKey               *rsa.PrivateKey `json:"-"`
	DecryptsAllowedPerPeriod int             `json`
	PeriodInSeconds          int             `json`
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

	// Basic sanity check:
	if !goodRSAPrefix || !goodRSASuffix {
		panic("RSA Private Key Invalid")
	}

	log.Println("Validating RSA private key...")
	block, _ := pem.Decode([]byte(RSAPrivateKeyString))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	HandleErr(err)

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
		RSAPrivKey:               privKey,
		DecryptsAllowedPerPeriod: decryptsPerPeriodInt,
		PeriodInSeconds:          periodInSecondsInt,
	}

	// Log everything except for RSA private key (sensitive):
	b, err := json.Marshal(cfg)
	HandleErr(err)
	log.Println(string(b))

	CFG = &cfg
}

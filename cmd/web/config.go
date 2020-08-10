package main

import (
	"log"
	"os"
	"strings"
)

type Config struct {
	// TODO: using Prod defaults (except for secure stuff hidden in credentials.yaml)
	SQLiteFilePath      string
	SeverHost           string
	ServerPort          string
	RSAPrivateKeyString string
	RSAPrivateKeyBytes  []byte
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

	SQLiteFilePath := defaultRead("SQLITE_FILEPATH", "opsep.db")
	SeverHost := defaultRead("SERVER_HOST", "localhost")
	ServerPort := defaultRead("SERVER_PORT", "80")
	RSAPrivateKey := strings.TrimSpace(os.Getenv("RSA_PRIVATE_KEY"))

	if strings.HasPrefix(RSAPrivateKey, "-----BEGIN RSA PRIVATE KEY-----") == false || strings.HasSuffix(RSAPrivateKey, "-----END RSA PRIVATE KEY-----") == false {
		panic("RSA Private Key Invalid")
	}

	cfg := Config{
		SQLiteFilePath:      SQLiteFilePath,
		SeverHost:           SeverHost,
		ServerPort:          ServerPort,
		RSAPrivateKeyString: RSAPrivateKey,
		RSAPrivateKeyBytes:  []byte(RSAPrivateKey),
	}

	CFG = &cfg
}

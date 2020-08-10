package main

import (
	"log"
	"os"
	"strings"
)

type Config struct {
	// TODO: using Prod defaults (except for secure stuff hidden in credentials.yaml)
	SQLiteFilePath     string
	SeverHost          string
	ServerPort         string
	RSAPrivateKeyBytes []byte
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

	cfg := Config{
		SQLiteFilePath:     defaultRead("SQLITE_FILEPATH", "opsep.db"),
		SeverHost:          defaultRead("SERVER_HOST", "localhost"),
		ServerPort:         defaultRead("SERVER_PORT", "80"),
		RSAPrivateKeyBytes: []byte(RSAPrivateKeyString),
	}

	CFG = &cfg
}

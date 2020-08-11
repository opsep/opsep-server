package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func SingleSHA256(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func DSha256Hex(data string) string {
	first := SingleSHA256(data)
	return SingleSHA256(first)
}
func OAEP256AsymmetricDecrypt(cipherText []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherText, nil)
	if err != nil {
		return []byte(""), fmt.Errorf("rsa.DecryptOAEP: %v", err)
	}
	// Trim extra newline byte:
	return bytes.TrimRight(plainText, "\n"), nil
}

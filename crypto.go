package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
func OAEP256AsymmetricDecrypt(cipherText []byte, rsaPrivKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(rsaPrivKeyPEM)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte(""), fmt.Errorf("x509.ParsePKCS1PrivateKey: %v", err)
	}
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherText, nil)
	if err != nil {
		return []byte(""), fmt.Errorf("rsa.DecryptOAEP: %v", err)
	}
	// TODO: Why is there an extra newline byte!?
	return bytes.TrimRight(plainText, "\n"), nil
}

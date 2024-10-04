package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
)

// PKCS7 padding
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := data[len(data)-1]
	if int(padding) > blockSize || padding == 0 {
		return nil, fmt.Errorf("padding size is invalid")
	}
	return data[:len(data)-int(padding)], nil
}

// AES decryption with CBC mode
func DecryptBody(encryptedHex string) (string, error) {
	key := []byte("6368616e676520746869732070617373")

	// Decode the hex string
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", fmt.Errorf("error decoding hex string: %v", err)
	}

	// Extract IV (first 16 bytes)
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %v", err)
	}

	// Decrypt the ciphertext
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted plaintext
	plaintext, err := pkcs7Unpad(ciphertext, block.BlockSize())
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {
	// Replace with the encrypted message from Node.js
	encryptedMessage := "778018c78996a4d7a318eaee20c9e9734c80fd47f9984e72bc0ed1db11db6872" // Example: "d9e9161f9...ff0ac"
	decryptedMessage, err := DecryptBody(encryptedMessage)
	if err != nil {
		log.Fatal("Error decrypting message:", err)
	}
	fmt.Println("Decrypted Message:", decryptedMessage)
}

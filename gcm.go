package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// GCM encryption
type GCM struct {
	Secret string
}

func NewGCM(secret string) *GCM {
	return &GCM{
		Secret: secret,
	}
}

// Encrypt payload using AES GCM encryption mode
func (gcmEnc *GCM) Encrypt(payload []byte) (string, string, string, error) {
	key := []byte(gcmEnc.Secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}

	encrypted := gcm.Seal(nonce, nonce, payload, nil)

	return string(encrypted), hex.EncodeToString(encrypted), base64.URLEncoding.EncodeToString(encrypted), nil
}

// Decrypt AES GCM encrypted input
func (gcmEnc *GCM) Decrypt(payload string) (string, error) {
	key := []byte(gcmEnc.Secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	byteIn := []byte(payload)
	nonceSize := gcm.NonceSize()

	if len(byteIn) < nonceSize {
		return "", errors.New("encrypted text too short")
	}

	nonce, encrypted := byteIn[:nonceSize], byteIn[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

package crypto

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Credits to: https://github.com/elithrar/simple-scrypt/blob/master/scrypt.go

// SCrypt hashing algorithm
type SCrypt struct {
	DK      []byte
	Salt    []byte
	N       int // 32768, should be the highest power of 2 derived within 100 milliseconds
	R       int // 8
	P       int // 1
	SaltLen int // 32
	KeyLen  int // 32
	SaltGen func(len int) ([]byte, error)
}

// NewSCrypt will initialize default SCrypt params
func NewSCrypt() *SCrypt {
	return &SCrypt{
		N:       32768,
		R:       8,
		P:       1,
		SaltLen: 32,
		KeyLen:  32,
		SaltGen: GenerateSalt,
	}
}

// Hash sCrypt.Plain
func (sCrypt *SCrypt) Hash(value string) (string, error) {
	salt, err := sCrypt.SaltGen(sCrypt.SaltLen)
	if err != nil {
		return "", err
	}

	sCrypt.Salt = salt

	dk, err := scrypt.Key([]byte(value), sCrypt.Salt, sCrypt.N, sCrypt.R, sCrypt.P, sCrypt.KeyLen)
	if err != nil {
		return "", err
	}
	sCrypt.DK = dk

	hashed := fmt.Sprintf("%d$%d$%d$%x$%x", sCrypt.N, sCrypt.R, sCrypt.P, sCrypt.Salt, sCrypt.DK)

	return hashed, nil
}

// Validate sCrypt.Plain against sCrypt.Hashed
func (sCrypt *SCrypt) Validate(hashed, plain string) error {
	existing, err := decodeSCryptHash(hashed)
	if err != nil {
		return err
	}

	dk, err := scrypt.Key([]byte(plain), existing.Salt, existing.N, existing.R, existing.P, existing.KeyLen)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(existing.DK, dk) == 1 {
		return nil
	}

	return errors.New("invalid hash")
}

// decodeSCryptHash
func decodeSCryptHash(hash string) (*SCrypt, error) {
	values := strings.Split(hash, "$")

	// P, N, R, Salt, scrypt derived key
	if len(values) != 5 {
		return nil, errors.New("invalid hash length")
	}

	sCrypt := &SCrypt{}
	var err error

	sCrypt.N, err = strconv.Atoi(values[0])
	if err != nil {
		return nil, err
	}

	sCrypt.R, err = strconv.Atoi(values[1])
	if err != nil {
		return nil, err
	}

	sCrypt.P, err = strconv.Atoi(values[2])
	if err != nil {
		return nil, err
	}

	sCrypt.Salt, err = hex.DecodeString(values[3])
	if err != nil {
		return nil, err
	}
	sCrypt.SaltLen = len(sCrypt.Salt)

	sCrypt.DK, err = hex.DecodeString(values[4])
	if err != nil {
		return nil, err
	}
	sCrypt.KeyLen = len(sCrypt.DK)

	return sCrypt, nil
}

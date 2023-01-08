package crypto

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Credits to: https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go

// Argon2 hashing algorithm
type Argon2 struct {
	DK      []byte
	Salt    []byte
	Time    uint32
	Memory  uint32
	Threads uint8
	SaltLen int
	KeyLen  uint32
	SaltGen func(len int) ([]byte, error)
}

// NewArgon2 will initialize default Argon2 params
func NewArgon2() *Argon2 {
	return &Argon2{
		Memory:  64 * 1024,
		Time:    3,
		Threads: 2,
		SaltLen: 32,
		KeyLen:  32,
		SaltGen: GenerateSalt,
	}
}

// Hash value using argon2 algorithm
func (argon *Argon2) Hash(value string) (string, error) {
	salt, err := argon.SaltGen(argon.SaltLen)
	if err != nil {
		return "", err
	}

	argon.Salt = salt

	dk := argon2.IDKey([]byte(value), argon.Salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)
	argon.DK = dk

	hashed := fmt.Sprintf("%d$%d$%d$%d$%x$%x", argon2.Version, argon.Memory, argon.Time, argon.Threads, argon.Salt, argon.DK)

	return hashed, nil
}

// Validate plain against hashed
func (argon *Argon2) Validate(hashed, plain string) error {
	existing, err := decodeArgonHash(hashed)
	if err != nil {
		return err
	}

	dk := argon2.IDKey([]byte(plain), existing.Salt, existing.Time, existing.Memory, existing.Threads, existing.KeyLen)

	if subtle.ConstantTimeCompare(existing.DK, dk) == 1 {
		return nil
	}

	return errors.New("invalid hash")
}

// decodeArgonHash
func decodeArgonHash(encodedHash string) (*Argon2, error) {
	values := strings.Split(encodedHash, "$")
	if len(values) != 6 {
		return nil, errors.New("invalid hash length")
	}

	argon := &Argon2{}

	version, err := strconv.Atoi(values[0])
	if err != nil {
		return nil, err
	}
	if version != argon2.Version {
		return nil, errors.New("incompatible argon2 version")
	}

	memory, err := strconv.Atoi(values[1])
	if err != nil {
		return nil, err
	}
	argon.Memory = uint32(memory)

	time, err := strconv.Atoi(values[2])
	if err != nil {
		return nil, err
	}
	argon.Time = uint32(time)

	threads, err := strconv.Atoi(values[3])
	if err != nil {
		return nil, err
	}
	argon.Threads = uint8(threads)

	argon.Salt, err = hex.DecodeString(values[4])
	if err != nil {
		return nil, err
	}
	argon.SaltLen = len(argon.Salt)

	argon.DK, err = hex.DecodeString(values[5])
	if err != nil {
		return nil, err
	}
	argon.KeyLen = uint32(len(argon.DK))

	return argon, nil
}

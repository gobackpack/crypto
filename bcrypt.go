package crypto

import (
	"golang.org/x/crypto/bcrypt"
)

// BCrypt hashing algorithm
type BCrypt struct {
	Cost int
}

// NewBCrypt will initialize default bcrypt params
func NewBCrypt() *BCrypt {
	return &BCrypt{
		Cost: bcrypt.DefaultCost,
	}
}

// Hash bCrypt.Plain
func (bCrypt *BCrypt) Hash(value string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(value), bCrypt.Cost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

// Validate bCrypt.Plain against bCrypt.Hashed
func (bCrypt *BCrypt) Validate(hashed, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}

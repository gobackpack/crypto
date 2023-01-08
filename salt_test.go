package crypto_test

import (
	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	salt, err := crypto.GenerateSalt(10)
	assert.NoError(t, err)
	assert.NotEmpty(t, salt)
	assert.Len(t, salt, 10)
}

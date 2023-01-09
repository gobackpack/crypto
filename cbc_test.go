package crypto_test

import (
	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCBC_Encrypt(t *testing.T) {
	cbc := crypto.NewCBC("3t6w9z$C&F)J@NcR", "KbPeShVmYq3t6w9z")

	encryptedRaw, encryptedHex, err := cbc.Encrypt([]byte("test-123"))
	assert.NoError(t, err)

	assert.Equal(t, "\x1c\xefi\xbb5I\xdd\xe3\xd6w\x13=y\xd5\x05:", encryptedRaw)
	assert.Equal(t, "1cef69bb3549dde3d677133d79d5053a", encryptedHex)
}

package TwoFaGo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"go.etcd.io/bbolt"
	"os"
	"time"
)

type storage struct {
	storagePath string
	db          *bbolt.DB
	aesKey      [32]byte
}

func (s *storage) Open() error {
	// makes the directory if it does not exist yet
	err := os.MkdirAll(s.storagePath, 0700)
	if err != nil {
		return err
	}

	s.db, err = bbolt.Open(s.storagePath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	return err
}

func decrypt(ciphertext []byte, aesKey [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encrypt(bytes []byte, aesKey [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, bytes, nil), nil
}

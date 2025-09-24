package TwoFaGo

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go.etcd.io/bbolt"
	"strings"
)

const (
	mfaSecretBucketName = "TOTPSecrets"
)

type TOTPStored struct {
	Issuer      string // e.g "cloudflare
	UserAccount string // e.g example@example.com
	Secret      string // base32 encoded secret
	Period      int    // in seconds, e.g. 30
	Algorithm   string // Can be "SHA1", "SHA256", "SHA512"
}

type BboltMFASecretStorage struct {
	db     *bbolt.DB
	aesKey [32]byte
}

func NewBboltMFASecretStorage(db *bbolt.DB, aesKey [32]byte) *BboltMFASecretStorage {
	return &BboltMFASecretStorage{db: db, aesKey: aesKey}
}

type TOTPSecretStorage interface {
	// StoreTOTPSecret stores the given MFA secret. If a secret with the same Secret field already exists, it is updated.
	StoreTOTPSecret(secret TOTPStored) error

	GetAllTOTPSecrets() ([]TOTPStored, error)

	DeleteTOTPSecretBySecret(secretStr string) error
}

func (s *BboltMFASecretStorage) StoreTOTPSecret(secret TOTPStored) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(mfaSecretBucketName))
		if err != nil {
			return err
		}

		foundDuplicate := false
		err = b.ForEach(func(k, v []byte) error {
			existingSecret, err := unmarshalAndDecryptSecret(v, s.aesKey)
			if err != nil {
				return err
			}
			if existingSecret.Secret == secret.Secret {
				encryptedSecret, err := marshalAndEncryptSecret(secret, s.aesKey)
				if err != nil {
					return err
				}
				b.Put(k, encryptedSecret)
				foundDuplicate = true
				return nil
			}
			return nil
		})
		if err != nil {
			return err
		}
		if foundDuplicate {
			return nil
		}

		// No duplicate found, create a new entry
		secret.Secret = strings.ToUpper(strings.TrimSpace(secret.Secret))

		// check if the algorithm is valid, must be SHA1, SHA256 or SHA512
		if secret.Algorithm != "SHA1" && secret.Algorithm != "SHA256" && secret.Algorithm != "SHA512" {
			return fmt.Errorf("invalid algorithm: %s", secret.Algorithm)
		}

		if secret.Period <= 0 {
			return fmt.Errorf("invalid period: %d", secret.Period)
		}

		encryptedSecret, err := marshalAndEncryptSecret(secret, s.aesKey)
		if err != nil {
			return err
		}
		id, _ := b.NextSequence()

		return b.Put(itob(id), encryptedSecret)
	})
}

func (s *BboltMFASecretStorage) GetAllTOTPSecrets() ([]TOTPStored, error) {
	var secrets []TOTPStored
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(mfaSecretBucketName))
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			secret, err := unmarshalAndDecryptSecret(v, s.aesKey)
			if err != nil {
				return err
			}

			secrets = append(secrets, secret)

			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (s *BboltMFASecretStorage) DeleteTOTPSecretBySecret(secretStr string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(mfaSecretBucketName))
		if b == nil {
			return nil
		}

		var keyToDelete []byte
		err := b.ForEach(func(k, v []byte) error {
			secret, err := unmarshalAndDecryptSecret(v, s.aesKey)
			if err != nil {
				return err
			}

			if secret.Secret == secretStr {
				keyToDelete = k
				return nil
			}
			return nil
		})
		if err != nil {
			return err
		}

		if keyToDelete != nil {
			return b.Delete(keyToDelete)
		}
		return nil
	})
}

func unmarshalAndDecryptSecret(data []byte, aesKey [32]byte) (TOTPStored, error) {
	var secret TOTPStored

	decrypted, err := decrypt(data, aesKey)
	if err != nil {
		return secret, err
	}

	err = json.Unmarshal(decrypted, &secret)
	if err != nil {
		return secret, err
	}

	return secret, nil
}

func marshalAndEncryptSecret(secret TOTPStored, aesKey [32]byte) ([]byte, error) {
	marshalled, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}

	return encrypt(marshalled, aesKey)
}

// itob aka IntToByte returns an 8-byte big endian representation of v.
func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

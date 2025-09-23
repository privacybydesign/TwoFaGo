package TwoFaGo

import (
	"fmt"
	"path/filepath"
)

type MFAClient struct {
	storagePath      string
	aesKey           [32]byte
	MFASecretStorage TOTPSecretStorage
}

func New(storagePath string, aesKey [32]byte) (*MFAClient, error) {
	storagePath = filepath.Join(storagePath, "twoFaSecrets")

	s := &storage{storagePath: storagePath, aesKey: aesKey}
	err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open 2fa storage: %w", err)
	}

	// Initialize the MFA secret storage
	mfaSecretStorage := NewBboltMFASecretStorage(s.db, aesKey)

	fmt.Println("MFA client initialized")

	return &MFAClient{
		storagePath:      storagePath,
		aesKey:           aesKey,
		MFASecretStorage: mfaSecretStorage,
	}, nil
}

func (c *MFAClient) Close() error {
	s := &storage{storagePath: c.storagePath, aesKey: c.aesKey, db: nil}
	return s.Close()
}

func (c *MFAClient) GetAllTOTPSecrets() ([]TOTPcode, error) {
	fmt.Println("Getting all TOTP codes")
	codes, err := GetAllCodes(c.MFASecretStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to get all TOTP codes: %w", err)
	}
	return codes, nil
}

func (c *MFAClient) StoreTOTPSecret(secret TOTPStored) error {
	err := c.MFASecretStorage.StoreTOTPSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return nil
}

package TwoFaGo

import "fmt"

type MFAClient struct {
	storagePath      string
	aesKey           [32]byte
	MFASecretStorage TOTPSecretStorage
}

func New(storagePath string, aesKey [32]byte) (*MFAClient, error) {
	s := &storage{storagePath: storagePath, aesKey: aesKey}
	err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open 2fa storage: %w", err)
	}

	// Initialize the MFA secret storage
	mfaSecretStorage := NewBboltMFASecretStorage(s.db, aesKey)

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

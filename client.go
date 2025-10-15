package TwoFaGo

import (
	"fmt"
	"path/filepath"
	"time"
)

type MFAClient struct {
	storagePath      string
	aesKey           [32]byte
	MFASecretStorage TOTPSecretStorage
	export           Export
	totp             TOTP
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

	client := &MFAClient{
		storagePath:      storagePath,
		aesKey:           aesKey,
		MFASecretStorage: mfaSecretStorage,
		export:           &exportImpl{},
		totp:             &TOTPImpl{s: mfaSecretStorage},
	}

	return client, nil
}

func (c *MFAClient) Close() error {
	s := &storage{storagePath: c.storagePath, aesKey: c.aesKey, db: nil}
	return s.Close()
}

func (c *MFAClient) GetAllTOTPSecrets() ([]TOTPcode, error) {
	codes, err := c.totp.GetAllCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to get all TOTP codes: %w", err)
	}
	return codes, nil
}

func (c *MFAClient) ExportSecrets() ([]TOTPStored, error) {
	secrets, err := c.MFASecretStorage.GetAllTOTPSecrets()
	if err != nil {
		return nil, fmt.Errorf("failed to export TOTP secrets: %w", err)
	}

	return secrets, nil
}

func (c *MFAClient) StoreTOTPSecret(secret TOTPStored) error {
	err := c.MFASecretStorage.StoreTOTPSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return nil
}

func (c *MFAClient) StoreTOTPSecretByURL(inputUrl string) error {
	err := c.export.ProcessURLTOTPCode(c.MFASecretStorage, inputUrl)
	if err != nil {
		return fmt.Errorf("failed to store TOTP secret by URL: %w", err)
	}

	return nil
}

func (c *MFAClient) RemoveTOTPSecretByCode(code TOTPcode) error {
	fmt.Println("removing " + code.UserAccount)
	timestamp := uint64(time.Now().Unix())
	err := c.totp.RemoveCodeByTOTPCode(code, timestamp)
	if err != nil {
		return fmt.Errorf("failed to remove TOTP secret by code: %w", err)
	}

	return nil
}

func (c *MFAClient) ExportSecretsToUrl(secrets []TOTPStored, isGoogle bool) ([]string, error) {
	if secrets == nil {
		return nil, fmt.Errorf("no secrets provided to export")
	}

	urls, err := c.export.ExportSecretsAsURL(secrets, isGoogle)
	if err != nil {
		return nil, fmt.Errorf("failed to export TOTP secrets to URL: %w", err)
	}

	return urls, nil
}

func (c *MFAClient) EncryptExportFile(password, fileContent string) (string, error) {
	encryptedContent, err := c.export.EncryptExportFile(password, fileContent)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt export file: %w", err)
	}

	return encryptedContent, nil
}

func (c *MFAClient) DecryptExportFile(password, encryptedContent string) (string, error) {
	decryptedContent, err := c.export.DecryptExportFile(password, encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt export file: %w", err)
	}

	return decryptedContent, nil
}

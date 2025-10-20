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

func New(storagePath string, aesKey [32]byte) *MFAClient {
	storagePath = filepath.Join(storagePath, "twoFaSecrets")

	fmt.Println("MFA client initialized")

	client := &MFAClient{
		storagePath:      storagePath,
		aesKey:           aesKey,
		MFASecretStorage: nil, // will be initialized in OpenStorage
		export:           &exportImpl{},
		totp:             &TOTPImpl{s: nil},
	}

	return client
}

// OpenStorage initializes and opens the storage for MFA secrets.
// We did this so we can always start the client without risk of errors but only open the storage when experimental features are enabled.
// so we don't need to restart the whole app when they're toggled and so integration tests run properly.
func (c *MFAClient) OpenStorage() error {
	// check if storage is already opened to avoid reopening
	if c.MFASecretStorage != nil {
		return nil
	}

	s := &storage{storagePath: c.storagePath, aesKey: c.aesKey}
	err := s.Open()
	if err != nil {
		return fmt.Errorf("failed to open 2fa storage: %w", err)
	}

	// Initialize the MFA secret storage
	mfaSecretStorage := NewBboltMFASecretStorage(s.db, c.aesKey)

	c.MFASecretStorage = mfaSecretStorage

	return nil
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

func (c *MFAClient) EncryptExportFile(fileContent, password string) (string, error) {
	Content, err := c.export.EncryptExportFile(password, fileContent)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt export file: %w", err)
	}

	return Content, nil
}

func (c *MFAClient) DecryptExportFile(encryptedContent, password string) (string, error) {
	Content, err := c.export.DecryptExportFile(password, encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt export file: %w", err)
	}

	return Content, nil
}

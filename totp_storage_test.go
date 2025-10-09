package TwoFaGo

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
	"os"
	"testing"
	"time"
)

var secretSample = TOTPStored{
	Issuer:      "yivi",
	Secret:      "JBSWY3DPEHPK3PXP",
	Period:      30,
	UserAccount: "test@test.com",
	Algorithm:   "SHA1",
}

var secretsSample = []TOTPStored{
	{
		Issuer:      "yivi",
		Secret:      "JBSWY3DPEHPK3PXP",
		Period:      30,
		UserAccount: "test@test.com",
		Algorithm:   "SHA1",
	}, {
		Issuer:      "yivi2",
		Secret:      "JBSWY3DPEHPK3PXP2",
		Period:      30,
		UserAccount: "test2@test.com",
		Algorithm:   "SHA1",
	},
}

func TestTOTPSecretStorage(t *testing.T) {
	RunTestWithTempBboltMfaStorage(t, "Store and retrieve MFA Secret", testStoreRetrieveTOTPSecret)
	RunTestWithTempBboltMfaStorage(t, "Store duplicate MFA Secret (by Secret field)", testStoreDuplicateTOTPSecret)
	RunTestWithTempBboltMfaStorage(t, "Store and retrieve multiple MFA Secrets", testStoreRetrieveMultipleTOTPSecret)
	RunTestWithTempBboltMfaStorage(t, "Remove MFA Secret by secret from multiple", testRemoveTOTPSecretBySecretFromMultiple)
	RunTestWithTempBboltMfaStorage(t, "Retrieve from empty storage", testRetrieveTOTPFromEmptyStorage)
}

func RunTestWithTempBboltMfaStorage(t *testing.T, name string, test func(t *testing.T, storage TOTPSecretStorage)) {
	success := t.Run(name, func(t *testing.T) {
		withTempBboltDb(t, "mfa_secret.db", func(db *bbolt.DB) {
			var aesKey [32]byte
			copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

			storage := NewBboltMFASecretStorage(db, aesKey)
			test(t, storage)
		})
	})
	require.True(t, success)
}

func testStoreRetrieveTOTPSecret(t *testing.T, storage TOTPSecretStorage) {
	err := storage.StoreTOTPSecret(secretSample)
	require.NoError(t, err)

	secrets, err := storage.GetAllTOTPSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 1)
	require.Equal(t, secretSample.Secret, secrets[0].Secret)
}

func testStoreDuplicateTOTPSecret(t *testing.T, storage TOTPSecretStorage) {
	var secretSampleDiffName = TOTPStored{
		Issuer:      "yivi-dupe",
		Secret:      "JBSWY3DPEHPK3PXP",
		Period:      30,
		UserAccount: "test@test.com",
		Algorithm:   "SHA1",
	}

	err := storage.StoreTOTPSecret(secretSample)
	require.NoError(t, err)

	err = storage.StoreTOTPSecret(secretSampleDiffName)
	require.NoError(t, err)

	secrets, err := storage.GetAllTOTPSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 1)
	require.Equal(t, secretSampleDiffName.Issuer, secrets[0].Issuer)
}

func testStoreRetrieveMultipleTOTPSecret(t *testing.T, storage TOTPSecretStorage) {
	for _, s := range secretsSample {
		err := storage.StoreTOTPSecret(s)
		require.NoError(t, err)
	}

	secrets, err := storage.GetAllTOTPSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 2)
	// verify both secrets present regardless of order
	found := map[string]bool{}
	for _, s := range secrets {
		found[s.Secret] = true
	}
	require.True(t, found[secretsSample[0].Secret])
	require.True(t, found[secretsSample[1].Secret])
}

func testRemoveTOTPSecretBySecretFromMultiple(t *testing.T, storage TOTPSecretStorage) {
	for _, s := range secretsSample {
		err := storage.StoreTOTPSecret(s)
		require.NoError(t, err)
	}

	err := storage.DeleteTOTPSecretBySecret(secretsSample[0].Secret)
	require.NoError(t, err)

	secrets, err := storage.GetAllTOTPSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 1)
	require.Equal(t, secretsSample[1].Secret, secrets[0].Secret)
}

func testRetrieveTOTPFromEmptyStorage(t *testing.T, storage TOTPSecretStorage) {
	secrets, err := storage.GetAllTOTPSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 0)
}

func withTempBboltDb(t *testing.T, fileName string, closure func(db *bbolt.DB)) {
	dir, err := os.MkdirTemp("", "client-*")
	require.NoError(t, err)

	dbFile := fmt.Sprintf("%s/%s", dir, fileName)
	db, err := bbolt.Open(dbFile, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	require.NoError(t, err)
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	defer db.Close()
	defer os.Remove(dbFile)
	defer os.Remove(dir)
	closure(db)
}

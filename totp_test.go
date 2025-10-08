package TwoFaGo

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

type testTOTPDataType struct {
	TOTPStored TOTPStored
	Timestamp  int64
	Expected   int
	Totpurl    string
}

func TestTOTP(t *testing.T) {
	testGenerateTOTPCodeList(t)
	testStoreGetCodes(t)
	testDeleteTOTPCodeByCode(t)
	testDeleteOffsetTOTPSecretByCode(t, 31, false)
	testDeleteOffsetTOTPSecretByCode(t, 61, true)
	testDeleteOffsetTOTPSecretByCode(t, -31, false)
	testDeleteOffsetTOTPSecretByCode(t, -61, true)
	testDeleteDuplicateIssuerUser(t)
	testInvalidAlgorithm(t)
	testInvalidPeriod(t)
	testStoreGoogleMigrationUrl(t)
	testExportGoogleMigrationUrl(t)
	testTOTPUrl(t)
}

func testGenerateTOTPCodeList(t *testing.T) {
	for i, testTOTP := range testTOTPs {
		typedTimestamp := uint64(testTOTP.Timestamp)
		typedExpected := uint32(testTOTP.Expected)

		code, err := GenerateCode(testTOTP.TOTPStored, typedTimestamp)
		require.NoError(t, err, fmt.Sprintf("test case %d failed: %v", i, err))
		require.Equal(t, typedExpected, code, fmt.Sprintf("test case %d failed: expected %d, got %d", i, typedExpected, code))
	}
}

func testStoreGetCodes(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// Store multiple secrets, we only need 3 for this test and because the test data contains some duplicates
	for _, testTOTP := range testTOTPs[:3] {
		err := TOTPStorage.StoreTOTPSecret(testTOTP.TOTPStored)
		require.NoError(t, err)
	}

	secrets, err := TOTPStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 3, len(secrets))

	// Check if the secrets match
	for i, secret := range secrets {
		require.Equal(t, testTOTPs[i].TOTPStored.Issuer, secret.Issuer)
		require.Equal(t, testTOTPs[i].TOTPStored.UserAccount, secret.UserAccount)
		require.Equal(t, testTOTPs[i].TOTPStored.Secret, secret.Secret)
		require.Equal(t, testTOTPs[i].TOTPStored.Period, secret.Period)
		require.Equal(t, testTOTPs[i].TOTPStored.Algorithm, secret.Algorithm)
	}

	codes, err := GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	require.Equal(t, 3, len(codes))

}

func testDeleteTOTPCodeByCode(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	err := TOTPStorage.StoreTOTPSecret(testTOTPs[0].TOTPStored)
	require.NoError(t, err)

	codes, err := GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	require.Equal(t, 1, len(codes))
	code := codes[0]

	currentTimestamp := uint64(time.Now().Unix())

	err = RemoveCodeByTOTPCode(TOTPStorage, code, currentTimestamp)
	require.NoError(t, err)

	codes, err = GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	require.Equal(t, 0, len(codes))

	err = RemoveCodeByTOTPCode(TOTPStorage, code, currentTimestamp)
	require.Error(t, err)
}

// testDeleteOffsetTOTPSecretByCode tests deleting a TOTP secret by code with a time offset to simulate processing delay or deletion at just the wrong time.
// secondsOffset: positive to simulate future, negative to simulate past
// requireExpired: if true, we expect the deletion to fail because the code is expired thus can't find a matching account
func testDeleteOffsetTOTPSecretByCode(t *testing.T, secondsOffset int, requireExpired bool) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	err := TOTPStorage.StoreTOTPSecret(testTOTPs[0].TOTPStored)
	require.NoError(t, err)

	codes, err := GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	require.Equal(t, 1, len(codes))
	code := codes[0]

	var currentTimestamp uint64

	if secondsOffset < 0 {
		currentTimestamp = uint64(time.Now().Unix()) + uint64(secondsOffset)
	} else {
		currentTimestamp = uint64(time.Now().Unix()) - uint64(secondsOffset)
	}

	err = RemoveCodeByTOTPCode(TOTPStorage, code, currentTimestamp)
	if requireExpired {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}

	codes, err = GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	if requireExpired {
		require.Equal(t, 1, len(codes))
	} else {
		require.Equal(t, 0, len(codes))
	}
}

// testDeleteDuplicateIssuerUser ensures that when there are multiple TOTP secrets with the same Issuer and UserAccount,
// deleting one of them by code only deletes the intended one.
// This is intended as a regression test for a bug where the first matching Issuer/UserAccount was always deleted instead of also checking the generated code (and thus secret).
func testDeleteDuplicateIssuerUser(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	for _, testTOTP := range testTOTPs[8:10] {
		err := TOTPStorage.StoreTOTPSecret(testTOTP.TOTPStored)
		require.NoError(t, err)
	}

	codes, err := GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	require.Equal(t, 2, len(codes))

	codeToDelete := codes[0]
	currentTimestamp := uint64(time.Now().Unix())
	err = RemoveCodeByTOTPCode(TOTPStorage, codeToDelete, currentTimestamp)
	require.NoError(t, err)

	codes, err = GetAllCodes(TOTPStorage)
	require.NoError(t, err)
	require.Equal(t, 1, len(codes))

	// Ensure the remaining code is the one that was not deleted
	remainingCode := codes[0]
	require.Equal(t, testTOTPs[9].TOTPStored.Issuer, remainingCode.Issuer)
	require.Equal(t, testTOTPs[9].TOTPStored.UserAccount, remainingCode.UserAccount)
	// we don't get the secret back, but we can regenerate the expected code and compare
	expectedCode, err := GenerateCode(testTOTPs[9].TOTPStored, currentTimestamp)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%06d", expectedCode), remainingCode.Code)
}

func testInvalidAlgorithm(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// Store a secret with an invalid algorithm
	invalidTOTP := testTOTPs[0]
	invalidTOTP.TOTPStored.Algorithm = "MD5"
	err := TOTPStorage.StoreTOTPSecret(invalidTOTP.TOTPStored)
	require.Error(t, err)
}

func testInvalidPeriod(t *testing.T) {
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// Store a secret with an invalid period
	invalidTOTP := testTOTPs[0]
	invalidTOTP.TOTPStored.Period = 0
	err := TOTPStorage.StoreTOTPSecret(invalidTOTP.TOTPStored)
	require.Error(t, err)
}

func testStoreGoogleMigrationUrl(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// Store a Google migration token
	url := testGoogleMigrationTOTPUris[0]
	err := ProcessURLTOTPCode(TOTPStorage, url)
	require.NoError(t, err)

	secrets, err := TOTPStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 2, len(secrets)) // the token contains 2 secrets
}

func testExportGoogleMigrationUrl(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)

	// Store multiple secrets, we only need 3 for this test and because the test data contains some duplicates
	for _, testTOTP := range testTOTPs[:3] {
		err := TOTPStorage.StoreTOTPSecret(testTOTP.TOTPStored)
		require.NoError(t, err)
	}

	urls, err := ExportSecretsAsURL(TOTPStorage, true)
	require.NoError(t, err)
	require.Equal(t, 1, len(urls)) // all 3 secrets should be in a single migration URL

	// Basic validation of the URL
	require.Contains(t, urls[0], "otpauth-migration://offline?data=")

	// set up a new storage and import the URL to verify round-trip
	TearDownTempTOTPStorage(t, TOTPStorage, storagePath)
	newStorage, newStoragePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, newStorage, newStoragePath)

	err = ProcessURLTOTPCode(newStorage, urls[0])
	require.NoError(t, err)

	secrets, err := newStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 3, len(secrets))
}

func testTOTPUrl(t *testing.T) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// test with the 3 TOTP secrets that have a Totpurl field
	for _, testTOTP := range testTOTPs[:3] {
		err := ProcessURLTOTPCode(TOTPStorage, testTOTP.Totpurl)
		require.NoError(t, err)
	}
	secrets, err := TOTPStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 3, len(secrets))

	// check if the data matches
	for i, secret := range secrets {
		require.Equal(t, testTOTPs[i].TOTPStored.Issuer, secret.Issuer)
		require.Equal(t, testTOTPs[i].TOTPStored.UserAccount, secret.UserAccount)
		require.Equal(t, testTOTPs[i].TOTPStored.Secret, secret.Secret)
		require.Equal(t, testTOTPs[i].TOTPStored.Period, secret.Period)
		require.Equal(t, testTOTPs[i].TOTPStored.Algorithm, secret.Algorithm)
	}
}

func SetUpTempTOTPStorage(t *testing.T) (TOTPSecretStorage, string) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	storagePath := fmt.Sprintf("testdata/totp_storage_%d", time.Now().UnixNano())

	s := &storage{storagePath: storagePath, aesKey: aesKey}
	err := s.Open()
	require.NoError(t, err)
	return NewBboltMFASecretStorage(s.db, aesKey), storagePath
}
func TearDownTempTOTPStorage(t *testing.T, storage TOTPSecretStorage, storagePath string) {
	if storage != nil {
		if s, ok := storage.(*BboltMFASecretStorage); ok {
			if s.db != nil {
				_ = s.db.Close() // close underlying DB to release file lock
			}
		}
		// If TOTPStorage implements Close, close it too (safe no-op if not)
		type closer interface{ Close() error }
		if c, ok := any(storage).(closer); ok {
			_ = c.Close()
		}
	}
	if err := os.RemoveAll(storagePath); err != nil {
		if !os.IsNotExist(err) {
			t.Logf("failed to remove test db file: %v", err)
		}
	}
}

var testTOTPs = []testTOTPDataType{
	{
		TOTPStored: TOTPStored{
			Issuer:      "test0",
			UserAccount: "example@example.com",
			Secret:      "CUCPSO6X2NA6PY23",
			Period:      30,
			Algorithm:   "SHA1",
		},
		// generated with https://it-tools.tech/otp-generator
		Timestamp: 1757510707,
		Expected:  646573,
		Totpurl:   "otpauth://totp/test0:example@example.com?issuer=test0&secret=CUCPSO6X2NA6PY23&period=30&algorithm=SHA1&digits=6",
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test1",
			UserAccount: "example@example.com",
			Secret:      "6BJOMFYN3ATB4R64",
			Period:      30,
			Algorithm:   "SHA1",
		},
		// generated with https://it-tools.tech/otp-generator
		Timestamp: 1757511094,
		Expected:  321701,
		Totpurl:   "otpauth://totp/test1:example@example.com?issuer=test1&secret=6BJOMFYN3ATB4R64&period=30&algorithm=SHA1&digits=6",
	}, {
		TOTPStored: TOTPStored{
			Issuer:      "test2",
			UserAccount: "example@example.com",
			Secret:      "JBSWY3DPEHPK3PXP",
			Period:      60,
			Algorithm:   "SHA1",
		},
		// generated with https://totp.danhersam.com/
		Timestamp: 1757510171,
		Expected:  960766,
		Totpurl:   "otpauth://totp/test2:example@example.com?issuer=test2&secret=JBSWY3DPEHPK3PXP&period=60&algorithm=SHA1&digits=6",
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test3",
			UserAccount: "example@example.com",
			Secret:      "JBSWY3DPEHPK3PXP",
			Period:      15,
			Algorithm:   "SHA1",
		},
		// generated with https://totp.danhersam.com/
		Timestamp: 1757510255,
		Expected:  300588,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test4",
			UserAccount: "example@example.com",
			Secret:      "H7X4ARNIFGQYANRS",
			Period:      30,
			Algorithm:   "SHA1",
		},
		// generated with https://it-tools.tech/otp-generator
		Timestamp: 1757510292,
		Expected:  936604,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test5",
			UserAccount: "example@example.com",
			Secret:      "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT",
			Period:      30,
			Algorithm:   "SHA256",
		},
		// generated with https://piellardj.github.io/totp-generator/
		Timestamp: 1757511456,
		Expected:  890113,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test6",
			UserAccount: "example@example.com",
			Secret:      "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT",
			Period:      15,
			Algorithm:   "SHA256",
		},
		// generated with https://piellardj.github.io/totp-generator/
		Timestamp: 1757511981,
		Expected:  317913,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test7",
			UserAccount: "example@example.com",
			Secret:      "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT",
			Period:      30,
			Algorithm:   "SHA512",
		},
		// generated with https://piellardj.github.io/totp-generator/
		Timestamp: 1757511517,
		Expected:  721131,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test8",
			UserAccount: "example@example.com",
			Secret:      "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT",
			Period:      60,
			Algorithm:   "SHA512",
		},
		// generated with https://piellardj.github.io/totp-generator/
		Timestamp: 1757511557,
		Expected:  634542,
	}, {
		TOTPStored: TOTPStored{
			Issuer:      "test-dupe",
			UserAccount: "example@example.com",
			Secret:      "CUCPSO6X2NA6PY23",
			Period:      30,
			Algorithm:   "SHA1",
		},
		// generated with https://it-tools.tech/otp-generator
		Timestamp: 1757510707,
		Expected:  646573,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test-dupe",
			UserAccount: "example@example.com",
			Secret:      "6BJOMFYN3ATB4R64",
			Period:      30,
			Algorithm:   "SHA1",
		},
		// generated with https://it-tools.tech/otp-generator
		Timestamp: 1757511094,
		Expected:  321701,
	},
}

var testGoogleMigrationTOTPUris = []string{
	// 2 codes from https://it-tools.tech/otp-generator generated with the app.
	"otpauth-migration://offline?data=CjwKCr9lJAuNoTFUmiwSCWRlbW8tdXNlchoISVQtVG9vbHMgASgBMAJCE2ViODM0NDE3NTkzODkyNDI0NjgKPAoKaqmhXS0ou7G7PhIJZGVtby11c2VyGghJVC1Ub29scyABKAEwAkITYjcyNTY2MTc1OTM4OTI0OTAxNhACGAEgAA%3D%3D",
}

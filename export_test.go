package TwoFaGo

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExport(t *testing.T) {
	testStoreGoogleMigrationUrl(t, &exportImpl{})
	testExportGoogleMigrationUrl(t, &exportImpl{})
	testTOTPUrl(t, &exportImpl{})

	testEncryptDecryptHappy(t, &exportImpl{})
	testEncryptDecryptWrongPassword(t, &exportImpl{})
	testEncryptDecryptNoPassword(t, &exportImpl{})
	testEncryptEmptyString(t, &exportImpl{})
}

func testStoreGoogleMigrationUrl(t *testing.T, export *exportImpl) {
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// Store a SHA1 Google migration token
	url := testGoogleMigrationTOTPUris[0]
	err := export.ProcessURLTOTPCode(TOTPStorage, url)
	require.NoError(t, err)

	// Store SHA256/512 migration token
	url = testGoogleMigrationTOTPUris[1]
	err = export.ProcessURLTOTPCode(TOTPStorage, url)
	require.NoError(t, err)

	secrets, err := TOTPStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 3, len(secrets)) // the token contains 3 secrets because one is a duplicate
}

func testExportGoogleMigrationUrl(t *testing.T, export *exportImpl) {
	// we don't have to store any secrets, we can just take some from the test data
	testData := []TOTPStored{
		testTOTPs[0].TOTPStored,
		testTOTPs[1].TOTPStored,
		testTOTPs[2].TOTPStored,
	}

	urls, err := export.ExportSecretsAsURL(testData, true)
	require.NoError(t, err)
	require.Equal(t, 1, len(urls)) // all 3 secrets should be in a single migration URL

	// set up a new storage and import the URL to verify round-trip to check if the export was correct
	// (we verified correctness of the import in testStoreGoogleMigrationUrl)
	newStorage, newStoragePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, newStorage, newStoragePath)

	err = export.ProcessURLTOTPCode(newStorage, urls[0])
	require.NoError(t, err)

	secrets, err := newStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 3, len(secrets))
}

func testTOTPUrl(t *testing.T, export *exportImpl) {
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// test with the 3 TOTP secrets that have a Totpurl field
	for _, testTOTP := range testTOTPs[:3] {
		err := export.ProcessURLTOTPCode(TOTPStorage, testTOTP.Totpurl)
		require.NoError(t, err)
	}
	secrets, err := TOTPStorage.GetAllTOTPSecrets()
	require.NoError(t, err)
	require.Equal(t, 3, len(secrets))

	for i, secret := range secrets {
		require.Equal(t, testTOTPs[i].TOTPStored.Issuer, secret.Issuer)
		require.Equal(t, testTOTPs[i].TOTPStored.UserAccount, secret.UserAccount)
		require.Equal(t, testTOTPs[i].TOTPStored.Secret, secret.Secret)
		require.Equal(t, testTOTPs[i].TOTPStored.Period, secret.Period)
		require.Equal(t, testTOTPs[i].TOTPStored.Algorithm, secret.Algorithm)
	}
}

func testEncryptDecryptHappy(t *testing.T, export *exportImpl) {
	for _, file := range rawTestFile {
		fileContent, err := export.EncryptExportFile("test", file)
		if err != nil {
			return
		}

		require.NotEmpty(t, fileContent)

		// decrypt the file content to verify it was encrypted correctly
		decryptedContent, err := export.DecryptExportFile("test", fileContent)
		require.NoError(t, err)
		require.Equal(t, file, decryptedContent)
	}
}

func testEncryptDecryptWrongPassword(t *testing.T, export *exportImpl) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// store some secrets
	for _, testTOTP := range testTOTPs {
		err := TOTPStorage.StoreTOTPSecret(testTOTP.TOTPStored)
		require.NoError(t, err)
	}

	// export to file
	fileContent, err := export.EncryptExportFile("testpassword", "testfilecontent")
	if err != nil {
		return
	}

	require.NotEmpty(t, fileContent)

	// try decrypting with wrong password
	_, err = export.DecryptExportFile("wrongpassword", fileContent)
	require.Error(t, err)
}

func testEncryptDecryptNoPassword(t *testing.T, export *exportImpl) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// store some secrets
	for _, testTOTP := range testTOTPs {
		err := TOTPStorage.StoreTOTPSecret(testTOTP.TOTPStored)
		require.NoError(t, err)
	}

	// export to file
	fileContent, err := export.EncryptExportFile("testpassword", "testfilecontent")
	if err != nil {
		return
	}

	require.NotEmpty(t, fileContent)

	// try decrypting with wrong password
	_, err = export.DecryptExportFile("", fileContent)
	require.Error(t, err)
}

func testEncryptEmptyString(t *testing.T, export *exportImpl) {
	// Setup temporary storage
	TOTPStorage, storagePath := SetUpTempTOTPStorage(t)
	defer TearDownTempTOTPStorage(t, TOTPStorage, storagePath)

	// store some secrets
	for _, testTOTP := range testTOTPs {
		err := TOTPStorage.StoreTOTPSecret(testTOTP.TOTPStored)
		require.NoError(t, err)
	}

	// export to file
	_, err := export.EncryptExportFile("testpassword", "")
	if err != nil {
		return
	}

	require.Error(t, err)
}

var rawTestFile = []string{
	"Issuer: OpenAI\\nAccount: test.nl\\nSecret: WL5RMI2PVYKEIQQNRB\\nPeriod: 30\\nAlgorithm: SHA1\\n\\nIssuer: Cloudflare\\nAccount: test.nl\\nSecret: WL5RMI2PVYKEIQQNR\\nPeriod: 30\\nAlgorithm: SHA1\\n\\nIssuer: Discord\\nAccount: test.nl\\nSecret: WL5RMI2PVYKEIQQNRD\\nPeriod: 30\\nAlgorithm: SHA1\\n\\n",
}

var testGoogleMigrationTOTPUris = []string{
	// 2 codes from https://it-tools.tech/otp-generator generated with the app.
	"otpauth-migration://offline?data=CjwKCr9lJAuNoTFUmiwSCWRlbW8tdXNlchoISVQtVG9vbHMgASgBMAJCE2ViODM0NDE3NTkzODkyNDI0NjgKPAoKaqmhXS0ou7G7PhIJZGVtby11c2VyGghJVC1Ub29scyABKAEwAkITYjcyNTY2MTc1OTM4OTI0OTAxNhACGAEgAA%3D%3D",
	// 2 codes from https://piellardj.github.io/totp-generator with sha256 and sha512 generated with the app.
	"otpauth-migration://offline?data=Ck8KFD1jwRTgK6xTGKA0gdTWaGMebxmTEg1UT1RQZ2VuZXJhdG9yGg1UT1RQZ2VuZXJhdG9yIAMoATACQhMwZGI1OTgxNzU5OTIyOTAyNDE3Ck8KFD1jwRTgK6xTGKA0gdTWaGMebxmTEg1UT1RQZ2VuZXJhdG9yGg1UT1RQZ2VuZXJhdG9yIAIoATACQhM5ODBmNWUxNzU5OTIyOTA3NzQ2EAIYASAA",
}

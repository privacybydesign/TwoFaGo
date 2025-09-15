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
}

func TestTOTP(t *testing.T) {
	testGenerateTOTPCodeList(t)
	testGetAllCodes(t)
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

func testGetAllCodes(t *testing.T) {
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

func SetUpTempTOTPStorage(t *testing.T) (TOTPSecretStorage, string) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	storagePath := fmt.Sprintf("testdata/totp_storage_%d.db", time.Now().UnixNano())

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
	if err := os.Remove(storagePath); err != nil {
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
	},
}

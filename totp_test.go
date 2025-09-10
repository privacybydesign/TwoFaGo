package TwoFaGo

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

type testTOTPDataType struct {
	TOTPStored TOTPStored
	Timestamp  int64
	Expected   int
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
			Period:      30,
			Algorithm:   "SHA512",
		},
		// generated with https://piellardj.github.io/totp-generator/
		Timestamp: 1757511517,
		Expected:  721131,
	},
	{
		TOTPStored: TOTPStored{
			Issuer:      "test7",
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

func TestTOTP(t *testing.T) {
	testGenerateTOTPCodeList(t)
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

package TwoFaGo

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
	"time"
)

type TOTPcode struct {
	Issuer        string
	UserAccount   string
	Code          string
	NextCode      string
	Period        int
	TimerProgress int
}

type TOTP interface {
	GenerateCode(timestamp uint64) (uint32, error)
	GetAllCodes(s *BboltMFASecretStorage) ([]TOTPcode, error)
}

func GenerateCode(storedTOTP TOTPStored, timestamp uint64) (uint32, error) {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(storedTOTP.Secret)
	if err != nil {
		return 0, err
	}

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, timestamp/uint64(storedTOTP.Period))

	var hashedBytes hash.Hash

	switch storedTOTP.Algorithm {
	case "SHA1":
		hashedBytes = hmac.New(sha1.New, secretBytes)
	case "SHA256":
		hashedBytes = hmac.New(sha256.New, secretBytes)
	case "SHA512":
		hashedBytes = hmac.New(sha512.New, secretBytes)
	}

	hashedBytes.Write(timeBytes) // Concat the timestamp byte slice
	h := hashedBytes.Sum(nil)    // Calculate 20-byte hash digest

	// AND the hash with 0x0F (15) to get a single-digit offset
	offset := h[len(h)-1] & 0x0F

	// Truncate the hash by the offset and convert it into a 32-bit
	// unsigned int. AND the 32-bit int with 0x7FFFFFFF (2147483647)
	// to get a 31-bit unsigned int.
	truncatedHash := binary.BigEndian.Uint32(h[offset:]) & 0x7FFFFFFF

	// The TOTP code is the truncated hashedBytes modulo 10^digits
	return truncatedHash % 1000000, nil
}

func GetAllCodes(s TOTPSecretStorage) ([]TOTPcode, error) {
	storedTOTPs, err := s.GetAllTOTPSecrets()
	if err != nil {
		return nil, err
	}

	var codes []TOTPcode
	for _, storedTOTP := range storedTOTPs {
		currentTimestamp := uint64(time.Now().Unix())
		nextTimestamp := currentTimestamp + uint64(storedTOTP.Period)

		currentCode, err := GenerateCode(storedTOTP, currentTimestamp)
		if err != nil {
			return nil, err
		}

		nextCode, err := GenerateCode(storedTOTP, nextTimestamp)
		if err != nil {
			return nil, err
		}

		timerProgress := int(currentTimestamp % uint64(storedTOTP.Period))

		codes = append(codes, TOTPcode{
			Issuer:        storedTOTP.Issuer,
			UserAccount:   storedTOTP.UserAccount,
			Code:          fmt.Sprintf("%06d", currentCode),
			NextCode:      fmt.Sprintf("%06d", nextCode),
			Period:        storedTOTP.Period,
			TimerProgress: timerProgress,
		})
	}
	return codes, nil
}

func RemoveCodeByTOTPCode(s TOTPSecretStorage, code TOTPcode, currentTimestamp uint64) error {
	secrets, err := s.GetAllTOTPSecrets()
	if err != nil {
		return err
	}

	// convert code.Code to int, then to uint32; I don't think we can do this in one step cleanly because of error handling which we ignore because we assume the code is always a valid 6-digit number since we generate it ourselves.
	intCode, _ := strconv.Atoi(code.Code)
	intCode32 := uint32(intCode)

	for _, secret := range secrets {
		if secret.UserAccount == code.UserAccount && secret.Issuer == code.Issuer {
			// check if the secret matches by regenerating the code and giving a 1-period leeway for clock drift and processing time
			currentCode, err := GenerateCode(secret, currentTimestamp)
			previousCode, err := GenerateCode(secret, currentTimestamp-uint64(secret.Period))
			nextCode, err := GenerateCode(secret, currentTimestamp+uint64(secret.Period))
			if err != nil {
				return err
			}
			if intCode32 == currentCode || intCode32 == previousCode || intCode32 == nextCode {
				return s.DeleteTOTPSecretBySecret(secret.Secret)
			}
		}
	}

	return fmt.Errorf("could not find TOTP secret for %s (%s)", code.UserAccount, code.Issuer)
}

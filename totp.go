package TwoFaGo

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"hash"
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

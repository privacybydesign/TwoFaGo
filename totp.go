package TwoFaGo

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"google.golang.org/protobuf/proto"
	"hash"
	"net/url"
	"strconv"
	"strings"
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
	ProcessURLTOTPCode(s TOTPSecretStorage, inputUrl string) error
	ExportSecretsAsURL(s TOTPSecretStorage, isGoogle bool) ([]string, error)
	RemoveCodeByTOTPCode(s TOTPSecretStorage, code TOTPcode, currentTimestamp uint64) error
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

func ProcessURLTOTPCode(s TOTPSecretStorage, inputUrl string) error {
	// URL-decode in case the data portion was percent-encoded (e.g. %3D for =)
	unescapedUrl, err := url.QueryUnescape(inputUrl)
	if err != nil {
		return fmt.Errorf("failed to URL-decode migration data: %w", err)
	}

	var secrets []TOTPStored

	if strings.HasPrefix(unescapedUrl, "otpauth://totp/") {
		secret, err := otpauthURLToTOTPStored(unescapedUrl)
		if err != nil {
			return fmt.Errorf("failed to process otpauth URL: %w", err)
		}
		secrets = append(secrets, secret)
	} else if strings.HasPrefix(unescapedUrl, "otpauth-migration://offline?data=") {
		googleSecrets, err := googleMigrationToTOTPStored(unescapedUrl)
		if err != nil {
			return fmt.Errorf("failed to process Google Authenticator migration URL: %w", err)
		}
		secrets = googleSecrets
	}

	for _, secret := range secrets {
		err := s.StoreTOTPSecret(secret)
		if err != nil {
			return fmt.Errorf("failed to store TOTP secret: %w", err)
		}
	}

	return nil
}

func ExportSecretsAsURL(secrets []TOTPStored, isGoogle bool) ([]string, error) {
	var urls []string
	if isGoogle {
		googleURL, err := totpStoredToGoogleMigration(secrets)
		if err != nil {
			return nil, fmt.Errorf("failed to convert TOTP secrets to Google Auth migration URL: %w", err)
		}

		urls = append(urls, googleURL)
	} else {
		return []string{}, fmt.Errorf("only Google Auth migration URL export is supported at this time")
	}

	return urls, nil
}

func totpStoredToGoogleMigration(secrets []TOTPStored) (string, error) {
	var migrationData MigrationPayload

	for _, secret := range secrets {
		var algorithm MigrationPayload_Algorithm
		switch strings.ToUpper(secret.Algorithm) {
		case "SHA1":
			algorithm = MigrationPayload_ALGORITHM_SHA1
		case "SHA256":
			algorithm = MigrationPayload_ALGORITHM_SHA256
		case "SHA512":
			algorithm = MigrationPayload_ALGORITHM_SHA512
		case "MD5":
			algorithm = MigrationPayload_ALGORITHM_MD5 // Not supported in our implementation but we'll error in the store function; this is just for completeness
		default:
			return "", fmt.Errorf("unsupported algorithm: %s", secret.Algorithm)
		}

		migrationData.OtpParameters = append(migrationData.OtpParameters, &MigrationPayload_OtpParameters{
			Issuer:    secret.Issuer,
			Name:      secret.UserAccount,
			Secret:    []byte(secret.Secret),
			Type:      MigrationPayload_OTP_TYPE_TOTP,
			Algorithm: algorithm,
			Digits:    MigrationPayload_DIGIT_COUNT_SIX, // We only support 6 digits in our implementation
		})
	}

	// Set the version to 2 as per the protobuf definition or the Google Authenticator app will error with "update in play store" on newer versions of the app
	migrationData.Version = 2

	encodedData, err := proto.Marshal(&migrationData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal protobuf data: %w", err)
	}

	base64Data := base64.StdEncoding.EncodeToString(encodedData)

	return "otpauth-migration://offline?data=" + base64Data, nil
}

// based this function on this blog post: https://zwyx.dev/blog/google-authenticator-export-format
func googleMigrationToTOTPStored(rawURL string) ([]TOTPStored, error) {
	encodedData := strings.TrimPrefix(rawURL, "otpauth-migration://offline?data=")
	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return []TOTPStored{}, fmt.Errorf("failed to decode base64 data: %w", err)
	}

	var migrationData MigrationPayload
	err = proto.Unmarshal(decodedData, &migrationData)
	if err != nil {
		return []TOTPStored{}, fmt.Errorf("failed to unmarshal protobuf data: %w", err)
	}

	if len(migrationData.OtpParameters) == 0 {
		return []TOTPStored{}, fmt.Errorf("no OTP parameters found in migration data")
	}

	var stored []TOTPStored
	for _, param := range migrationData.OtpParameters {
		if param.Type != MigrationPayload_OTP_TYPE_TOTP {
			return []TOTPStored{}, fmt.Errorf("unsupported OTP type: %v", param.Type)
		}

		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(param.Secret)

		algorithm := "SHA1"
		switch param.Algorithm {
		case MigrationPayload_ALGORITHM_SHA1:
			algorithm = "SHA1"
		case MigrationPayload_ALGORITHM_SHA256:
			algorithm = "SHA256"
		case MigrationPayload_ALGORITHM_SHA512:
			algorithm = "SHA512"
		case MigrationPayload_ALGORITHM_MD5:
			algorithm = "MD5" // Not supported in our implementation but we'll error in the store function; this is just for completeness
		}

		// we don't support codes other than 6 digits for now
		if param.Digits != MigrationPayload_DIGIT_COUNT_SIX {
			return []TOTPStored{}, fmt.Errorf("unsupported number of digits: %v", param.Digits)
		}

		// add the TOTPStored to the list
		stored = append(stored, TOTPStored{
			Issuer:      param.Issuer,
			UserAccount: param.Name,
			Secret:      secret,
			Algorithm:   algorithm,
			Period:      30, // Google Authenticator uses a fixed period of 30 seconds
		})
	}
	return stored, nil

}

func otpauthURLToTOTPStored(rawURL string) (TOTPStored, error) {
	parsedUrl, err := url.Parse(rawURL)
	if err != nil {
		return TOTPStored{}, fmt.Errorf("failed to parse TOTP URL: %w", err)
	}

	if parsedUrl.Scheme != "otpauth" || parsedUrl.Host != "totp" {
		return TOTPStored{}, fmt.Errorf("invalid TOTP URL")
	}

	secret := parsedUrl.Query().Get("secret")
	algorithm := parsedUrl.Query().Get("algorithm")
	period := parsedUrl.Query().Get("period")
	issuer := parsedUrl.Query().Get("issuer")

	// get the user account from the path, which is in the format /Issuer:UserAccount or /UserAccount
	userAccount := strings.TrimPrefix(parsedUrl.Path, "/")
	if strings.Contains(userAccount, ":") {
		parts := strings.SplitN(userAccount, ":", 2)
		if issuer == "" {
			issuer = parts[0]
		}
		userAccount = parts[1]
	}

	periodInt := 30
	if period != "" {
		periodInt, err = strconv.Atoi(period)
		if err != nil || periodInt <= 0 {
			return TOTPStored{}, fmt.Errorf("invalid period: %s", period)
		}
	}

	algorithm = strings.ToUpper(strings.TrimSpace(algorithm))
	if algorithm == "" {
		algorithm = "SHA1"
	}

	return TOTPStored{
		Issuer:      issuer,
		UserAccount: userAccount,
		Secret:      strings.ToUpper(strings.TrimSpace(secret)),
		Algorithm:   algorithm,
		Period:      periodInt,
	}, nil
}

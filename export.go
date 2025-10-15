package TwoFaGo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
	"net/url"
	"strconv"
	"strings"
)

type Export interface {
	ProcessURLTOTPCode(s TOTPSecretStorage, inputUrl string) error
	ExportSecretsAsURL(secrets []TOTPStored, isGoogle bool) ([]string, error)
	EncryptExportFile(password, fileContent string) (string, error)
	DecryptExportFile(password, envelope string) (string, error)
}

type exportImpl struct{}

func (e *exportImpl) ProcessURLTOTPCode(s TOTPSecretStorage, inputUrl string) error {
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

func (e *exportImpl) ExportSecretsAsURL(secrets []TOTPStored, isGoogle bool) ([]string, error) {
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

// EncryptExportFile encrypts the file using Argon2id (RFC 9106, memory-constrained profile) to derive a 256-bit key,
// then AES-256-GCM to encrypt the file content. The returned string is a self-describing envelope:
// $argon2id$v=<ver>$m=<mem>,t=<iter>,p=<par>$<salt_b64url_nopad>$<nonce||ciphertext_b64url_nopad>
func (e *exportImpl) EncryptExportFile(password, fileContent string) (string, error) {
	if fileContent == "" {
		return "", fmt.Errorf("file content is empty")
	}

	// Argon2id parameters (RFC 9106, memory-constrained): t=3, m=64 MiB, p=4, keyLen=32
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	const (
		iter   uint32 = 3
		memory uint32 = 64 * 1024
		par    uint8  = 4
		keyLen uint32 = 32
	)

	key := argon2.IDKey([]byte(password), salt, iter, memory, par, keyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	cipherBlob := gcm.Seal(append([]byte{}, nonce...), nonce, []byte(fileContent), nil) // prefix nonce

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedBlob := base64.RawStdEncoding.EncodeToString(cipherBlob)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iter, par, encodedSalt, encodedBlob), nil
}

// DecryptExportFile reverses EncryptExportFile given the same password.
func (e *exportImpl) DecryptExportFile(password, envelope string) (string, error) {
	// Split on '$' and ignore empty segments that can occur from leading '$'
	parts := make([]string, 0)
	for _, p := range strings.Split(envelope, "$") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid envelope format")
	}
	if parts[0] != "argon2id" {
		return "", fmt.Errorf("unsupported KDF: %s", parts[0])
	}
	// parts[1] is like v=19 (argon2.Version)
	// parts[2] is like m=65536,t=3,p=4
	params := parts[2]
	var memory uint32
	var iter uint32
	var par uint8
	for _, kv := range strings.Split(params, ",") {
		if strings.HasPrefix(kv, "m=") {
			v := strings.TrimPrefix(kv, "m=")
			if mv, err := strconv.Atoi(v); err == nil {
				memory = uint32(mv)
			}
		} else if strings.HasPrefix(kv, "t=") {
			v := strings.TrimPrefix(kv, "t=")
			if tv, err := strconv.Atoi(v); err == nil {
				iter = uint32(tv)
			}
		} else if strings.HasPrefix(kv, "p=") {
			v := strings.TrimPrefix(kv, "p=")
			if pv, err := strconv.Atoi(v); err == nil {
				par = uint8(pv)
			}
		}
	}
	if memory == 0 || iter == 0 || par == 0 {
		return "", fmt.Errorf("invalid Argon2 parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %w", err)
	}
	blob, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	if len(blob) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}

	key := argon2.IDKey([]byte(password), salt, iter, memory, par, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return "", fmt.Errorf("ciphertext missing nonce")
	}
	nonce := blob[:nonceSize]
	ct := blob[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(pt), nil
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
			algorithm = MigrationPayload_ALGORITHM_MD5 // Not supported in our implementation, but we'll error in the store function; this is just for completeness
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
			algorithm = "MD5" // Not supported in our implementation, but we'll error in the store function; this is just for completeness
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

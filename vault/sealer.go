package vault

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"

	"github.com/provideapp/vault/common"
	vaultcrypto "github.com/provideapp/vault/crypto"
)

var (
	// unsealerKey is the encryption/decryption key for the vault keys,
	// which are used to decrypt the private keys/seeds
	unsealerKey []byte

	// unsealerCloakingKey will ensure Unsealer Key is encrypted in memory until required
	unsealerCloakingKey []byte
)

// SealUnsealRequestResponse provides the unseal information
type SealUnsealRequestResponse struct {
	UnsealerKey    *string `json:"key,omitempty"`
	ValidationHash *string `json:"validation_hash,omitempty"`
}

// ClearUnsealerKey clears the unsealer key - used to seal the vault (handler not implemented)
func ClearUnsealerKey(passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("error sealing vault. no unsealer key provided")
	}

	// get the SHA512 hash of the generated unsealerkey
	incomingKeyHash := crypto.SHA256.New()
	_, err := incomingKeyHash.Write([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("error sealing vault. error hashing incoming key")
	}

	if common.UnsealerKeyValidationHash == "" {
		return fmt.Errorf("error sealing vault. no seal unseal validation hash present")
	}

	validator, _ := hex.DecodeString(common.UnsealerKeyValidationHash)

	// validate the SHA256 hash against the validation hash
	res := bytes.Compare(incomingKeyHash.Sum(nil), validator[:])
	if res != 0 {
		return fmt.Errorf("error sealing vault. unsealer key doesn't match validation hash")
	}
	common.Log.Debugf("Seal vault: valid vault unsealing key received")

	unsealerKey = nil
	unsealerCloakingKey = nil
	return nil
}

// IsSealed checks to see if the vault is sealed (true) or unsealed (false)
func IsSealed() bool {
	if unsealerKey == nil {
		return true
	}
	return false
}

// SetUnsealerKey sets the unsealer key; this only possible with a SEALED vault
func SetUnsealerKey(passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("error unsealing vault; no unsealer key provided")
	}

	// we can't unseal an unsealed vault
	if unsealerKey != nil {
		return nil
	}

	// get the SHA512 hash of the generated unsealerkey
	incomingKeyHash := crypto.SHA256.New()
	_, err := incomingKeyHash.Write([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("error unsealing vault; error hashing incoming key")
	}

	if common.UnsealerKeyValidationHash == "" {
		return fmt.Errorf("error unsealing vault; empty validation hash")
	}

	validator, _ := hex.DecodeString(common.UnsealerKeyValidationHash)

	// validate the SHA256 hash against the validation hash
	res := bytes.Compare(incomingKeyHash.Sum(nil), validator[:])
	if res != 0 {
		return fmt.Errorf("error unsealing vault; unsealer key provided doesn't match validator hash")
	}
	common.Log.Debugf("valid vault unsealing key received")

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault; failed to generate cloaking key")
	}

	// set the cloaking key to this random key
	unsealerCloakingKey = randomKey

	// convert the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{
		PrivateKey: &randomKey,
	}

	// get the original 32-byte entropy from the seed phrase - we will use this as the AES encryption key for the vaults
	unsealerKeySeed, err := vaultcrypto.GetEntropyFromMnemonic(passphrase)
	if err != nil {
		return fmt.Errorf("error unsealing vault; recovering entropy from BIP39 passphrase failed")
	}

	if len(unsealerKeySeed) != common.UnsealerKeyRequiredBytes {
		return fmt.Errorf("error unsealing vault; entropy not 32-bytes (required for AES encryption and required minimum for vault security)")
	}

	// encrypt the unsealer key with the cloaking key
	cloakedUnsealerKey, err := cloakingKey.Encrypt(unsealerKeySeed, nil)
	if err != nil {
		return fmt.Errorf("error unsealing vault; failed to encrypt unsealer with cloaking key")
	}

	// wipe the unsealer key seed in memory before garbage collection
	unsealerKeySeed, _ = common.RandomBytes(32)

	// set the vault unsealer key
	unsealerKey = cloakedUnsealerKey
	return nil
}

func getUnsealerKey() (*[]byte, error) {
	if unsealerCloakingKey == nil {
		return nil, fmt.Errorf("error unsealing vault; no cloaking key available")
	}

	// convert the cloaking key into an AES key
	cloakingKey := vaultcrypto.AES256GCM{
		PrivateKey: &unsealerCloakingKey,
	}

	// decrypt the unsealer key with the cloaking key
	encryptedUnsealerKey := unsealerKey

	unsealerKey, err := cloakingKey.Decrypt(
		encryptedUnsealerKey[NonceSizeSymmetric:],
		encryptedUnsealerKey[0:NonceSizeSymmetric],
	)

	if err != nil {
		return nil, fmt.Errorf("error decrypting unsealer key %s", err.Error())
	}

	return &unsealerKey, nil
}

func seal(unsealedKey *[]byte) (*[]byte, error) {
	if unsealerKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}

	if unsealedKey == nil {
		return nil, fmt.Errorf("error sealing vault; no unsealed key")
	}

	var err error
	sealerKey := vaultcrypto.AES256GCM{}
	sealerKey.PrivateKey, err = getUnsealerKey()
	if err != nil {
		return nil, fmt.Errorf("error sealing vault %s", err.Error())
	}

	sealedKey, err := sealerKey.Encrypt(*unsealedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error sealing vault: %s", err.Error())
	}

	return &sealedKey, nil
}

// unseal decrypts the sealed material with the unsealer key
func unseal(sealedKey *[]byte) (*[]byte, error) {
	if unsealerKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}

	if sealedKey == nil {
		return nil, fmt.Errorf("error unsealing vault; no sealed key")
	}

	var err error
	unsealerKey := vaultcrypto.AES256GCM{}
	unsealerKey.PrivateKey, err = getUnsealerKey()
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault %s", err.Error())
	}

	encryptedData := *sealedKey
	unsealedKey, err := unsealerKey.Decrypt(encryptedData[NonceSizeSymmetric:], encryptedData[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault; %s", err.Error())
	}

	return &unsealedKey, nil
}

// CreateUnsealerKey creates a fresh unsealer key
func CreateUnsealerKey() (*SealUnsealRequestResponse, error) {
	key, err := vaultcrypto.CreateHDWalletSeedPhrase()
	if err != nil {
		return nil, err
	}

	seedKey := key.Seed
	seedPhrase := string(*seedKey)

	// get the SHA256 hash of the generated unsealerkey
	validationHash := crypto.SHA256.New()
	_, err = validationHash.Write([]byte(*seedKey))
	if err != nil {
		return nil, err
	}

	responseHash := common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(validationHash.Sum(nil))))

	response := SealUnsealRequestResponse{
		UnsealerKey:    &seedPhrase,
		ValidationHash: responseHash,
	}

	return &response, nil
}

// vaultIsSealed returns true if the vault is sealed
func vaultIsSealed() bool {
	if unsealerKey == nil {
		return true
	}
	return false
}

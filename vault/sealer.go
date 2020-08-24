package vault

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/provideapp/vault/common"
	vaultcrypto "github.com/provideapp/vault/crypto"
)

// SealUnsealRequest provides the unseal information
type SealUnsealRequest struct {
	UnsealerKey *string `json:"unsealerkey,omitempty"`
}

// NewUnsealerKeyResponse is the struct returned when creating a new UnsealerKey
type NewUnsealerKeyResponse struct {
	UnsealerKey    *string `json:"unsealerkey,omitempty"`
	ValidationHash *string `json:"validationhash,omitempty"`
}

// UnsealerKey is the encryption/decryption key for the vault keys
// which are used to decrypt the private keys/seeds
var UnsealerKey []byte

// CloakingKey will ensure Infinity Key is encrypted in memory until required
var CloakingKey []byte

// UnsealerKeyRequiredBytes is the required length of the UnsealerKey in bytes
const UnsealerKeyRequiredBytes = 32

// SetUnsealerKey sets the Unsealer Key
// This is only possible with a SEALED vault
func SetUnsealerKey(passphrase string) error {

	if passphrase == "" {
		return fmt.Errorf("error unsealing vault (100)") //no unsealer key provided
	}

	// we can't unseal an unsealed application
	if UnsealerKey != nil {
		return fmt.Errorf("error unsealing vault (200)") //application already unsealed
	}

	// get the SHA512 hash of the generated unsealerkey
	incomingKeyHash := crypto.SHA256.New()
	_, err := incomingKeyHash.Write([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("error unsealing vault (300)") //error hashing incoming key
	}

	testy := os.Getenv("USK_VALIDATION_HASH")
	if common.UnsealerKeyValidator == "" {
		return fmt.Errorf("here - no validation key available (again!) - should be %s", testy)
	}

	validator, _ := hex.DecodeString(common.UnsealerKeyValidator)

	// validate the SHA256 hash against the validation hash
	res := bytes.Compare(incomingKeyHash.Sum(nil), validator[:])
	if res != 0 {
		return fmt.Errorf("error unsealing vault (400) expected %s, got %s (validator location %p)", common.UnsealerKeyValidator, string(incomingKeyHash.Sum(nil)), &common.UnsealerKeyValidator) //unsealer key provided doesn't match validator hash
	}
	if res == 0 {
		common.Log.Debugf("valid vault unsealing key received")
	}

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault (500)") //error setting up cloaking key
	}

	// set the cloaking key to this random key
	CloakingKey = randomKey

	// convert the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = &randomKey

	// get the original 32-byte entropy from the seed phrase - we will use this as the AES encryption key for the vaults
	unsealerKeySeed, err := vaultcrypto.GetEntropyFromMnemonic(passphrase)
	if err != nil {
		return fmt.Errorf("error unsealing vault (600)") //error recovering entropy from BIP39 passphrase
	}

	if len(unsealerKeySeed) != UnsealerKeyRequiredBytes {
		return fmt.Errorf("error unsealing vault (700)") //error with entropy not being 32-bytes (required for AES encryption and required minimum for vault security)
	}

	// encrypt the unsealer key with the cloaking key
	unsealerKey, err := cloakingKey.Encrypt(unsealerKeySeed, nil)
	if err != nil {
		return fmt.Errorf("error unsealing vault (800)") //error encrypting unsealer key with cloaking key
	}

	// wipe the unsealerkeyseed in memory before garbage collection
	unsealerKeySeed, _ = common.RandomBytes(32)

	// set the vault unsealer key
	UnsealerKey = unsealerKey
	return nil
}

func getUnsealerKey() (*[]byte, error) {
	if CloakingKey == nil {
		return nil, fmt.Errorf("error unsealing vault (1100)") //no cloaking key available
	}

	// convert the cloaking key into an AES key
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = &CloakingKey

	// decrypt the unsealer key with the cloaking key
	encryptedInfinityKey := UnsealerKey

	unsealerKey, err := cloakingKey.Decrypt(encryptedInfinityKey[NonceSizeSymmetric:], encryptedInfinityKey[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault (1200)") //could not decrypt unsealer key with cloaking key
	}

	return &unsealerKey, nil
}

func seal(unsealedKey *[]byte) (*[]byte, error) {
	if UnsealerKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}

	if unsealedKey == nil || *unsealedKey == nil {
		return nil, fmt.Errorf("nothing to seal")
	}

	var err error
	sealerKey := vaultcrypto.AES256GCM{}
	sealerKey.PrivateKey, err = getUnsealerKey()
	if err != nil {
		return nil, fmt.Errorf("error sealing vault %s", err.Error())
	}

	sealedKey, err := sealerKey.Encrypt(*unsealedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error while sealing: %s", err.Error())
	}

	return &sealedKey, nil
}

// unseal decrypts the sealed material with the infinity key
func unseal(sealedKey *[]byte) (*[]byte, error) {
	if UnsealerKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}
	if sealedKey == nil || *sealedKey == nil {
		return nil, fmt.Errorf("nothing to unseal")
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
		return nil, fmt.Errorf("error while unsealing")
	}
	return &unsealedKey, nil
}

// CreateUnsealerKey creates a fresh unsealer key
func CreateUnsealerKey() (*NewUnsealerKeyResponse, error) {

	newkey, err := vaultcrypto.CreateHDWalletSeedPhrase()
	if err != nil {
		return nil, err
	}

	seedKey := newkey.Seed
	seedPhrase := string(*seedKey)

	// get the SHA256 hash of the generated unsealerkey
	validationHash := crypto.SHA256.New()
	_, err = validationHash.Write([]byte(*seedKey))
	if err != nil {
		return nil, err
	}

	responseHash := common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(validationHash.Sum(nil))))

	response := NewUnsealerKeyResponse{}
	response.UnsealerKey = &seedPhrase
	response.ValidationHash = responseHash

	return &response, nil
}

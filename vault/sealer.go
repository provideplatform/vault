package vault

import (
	"fmt"

	vaultcrypto "github.com/provideapp/vault/crypto"
)

// InfinityKey is the encryption/decryption key for the vault keys
// which are used to decrypt the private keys/seeds
// initial implementation has this unencrypted in memory
// secondary implementation will encrypt this with derived key (or similar)
var InfinityKey *[]byte

// CloakingKey will ensure Infinity Key is encrypted in memory until required
var CloakingKey *[]byte

// SealUnsealRequest provides the seal/unseal information
type SealUnsealRequest struct {
	UnsealKey *string `json:"unseal,omitempty"`
	SealKey   *string `json:"seal,omitempty"`
}

// SetInfinityKey sets the Infinity Key
func SetInfinityKey(key *[]byte) error {
	if key == nil {
		return fmt.Errorf("error unsealing vault (100)")
	}

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault (200)")
	}

	// set the cloaking key to this random key
	CloakingKey = &randomKey

	// conver the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = &randomKey

	// encrypt the infinity key with the cloaking key
	infinityKey, err := cloakingKey.Encrypt(*key, nil)
	if err != nil {
		return fmt.Errorf("error unsealing vault (300)")
	}
	InfinityKey = &infinityKey
	return nil
}

func getInfinityKey() (*[]byte, error) {
	if CloakingKey == nil {
		return nil, fmt.Errorf("error unsealing vault (400)")
	}

	// convert the cloaking key into an AES key
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = CloakingKey

	// decrypt the infinity key with the cloaking key
	encryptedInfinityKey := *InfinityKey

	infinityKey, err := cloakingKey.Decrypt(encryptedInfinityKey[NonceSizeSymmetric:], encryptedInfinityKey[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault (500)")
	}

	return &infinityKey, nil
}

// seal encrypts the unsealed material with the infinity key
func seal(unsealedKey *[]byte) (*[]byte, error) {
	if InfinityKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}

	if unsealedKey == nil || *unsealedKey == nil {
		return nil, fmt.Errorf("nothing to seal")
	}

	var err error
	sealerKey := vaultcrypto.AES256GCM{}
	sealerKey.PrivateKey, err = getInfinityKey()
	if err != nil {
		return nil, fmt.Errorf("error sealing vault %s", err.Error())
	}
	sealedKey, err := sealerKey.Encrypt(*unsealedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error while sealing")
	}

	return &sealedKey, nil
}

// unseal decrypts the sealed material with the infinity key
func unseal(sealedKey *[]byte) (*[]byte, error) {
	if InfinityKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}
	if sealedKey == nil || *sealedKey == nil {
		return nil, fmt.Errorf("nothing to unseal")
	}

	var err error
	unsealerKey := vaultcrypto.AES256GCM{}
	unsealerKey.PrivateKey, err = getInfinityKey()
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

// CreateInfinityKey is a WIP method to create a new master unlock key
func CreateInfinityKey() ([]byte, error) {
	infinitykey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return nil, err
	}
	return infinitykey, nil
}

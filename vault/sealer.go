package vault

import (
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

// SetUnsealerKey sets the Unsealer Key
// This is only possible with a SEALED vault
func SetUnsealerKey(key *[]byte) error {
	if key == nil {
		return fmt.Errorf("error unsealing vault (100)")
	}

	// we can't unseal an unsealed application
	if UnsealerKey != nil {
		return fmt.Errorf("error unsealing vault (109)")
	}

	//check the unsealer key against the hash
	// get the SHA512 hash of the generated unsealerkey
	incomingKeyHash := crypto.SHA512.New()
	_, err := incomingKeyHash.Write(*key)
	if err != nil {
		return fmt.Errorf("error unsealing vault (200)")
	}

	incomingKeyHashHex := hex.EncodeToString(incomingKeyHash.Sum(nil))

	if UskValidationHash == nil {
		return fmt.Errorf("error unsealing vault (300) validation hash not set")
	}

	// common.Log.Debugf("init: database name %s", os.Getenv("DATABASE_NAME"))
	// common.Log.Debugf("init: validation hash %s", *UskValidationHash)

	// common.Log.Debugf("incoming key hash hex: %s", incomingKeyHashHex)

	if UskValidationHash != nil {
		if incomingKeyHashHex != *UskValidationHash {
			return fmt.Errorf("error unsealing vault (400) got %s, expected %s (hash mem location %p) - TempCounter: %d", incomingKeyHashHex, *UskValidationHash, UskValidationHash, TempCounter)
		}
	}

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault (500)")
	}

	// set the cloaking key to this random key
	CloakingKey = &randomKey

	// conver the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = &randomKey

	// encrypt the unsealer key with the cloaking key
	unsealerKey, err := cloakingKey.Encrypt(*key, nil)
	if err != nil {
		return fmt.Errorf("error unsealing vault (300)")
	}

	UnsealerKey = &unsealerKey
	return nil
}

func getUnsealerKey() (*[]byte, error) {
	if CloakingKey == nil {
		return nil, fmt.Errorf("error unsealing vault (400)")
	}

	// convert the cloaking key into an AES key
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = CloakingKey

	// decrypt the unsealer key with the cloaking key
	encryptedInfinityKey := *UnsealerKey

	unsealerKey, err := cloakingKey.Decrypt(encryptedInfinityKey[NonceSizeSymmetric:], encryptedInfinityKey[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault (500)")
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
		return nil, fmt.Errorf("error while sealing")
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
	unsealerKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return nil, err
	}

	// get the SHA512 hash of the generated unsealerkey
	validationHash := crypto.SHA512.New()
	_, err = validationHash.Write(unsealerKey)
	if err != nil {
		return nil, err
	}

	response := NewUnsealerKeyResponse{}
	key := hex.EncodeToString(unsealerKey)
	hash := hex.EncodeToString(validationHash.Sum(nil))
	response.UnsealerKey = &key
	response.ValidationHash = &hash

	return &response, nil
}

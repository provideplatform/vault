package vault

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"

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

// SetUnsealerKey sets the Unsealer Key
// This is only possible with a SEALED vault
func SetUnsealerKey(key *[]byte) error {

	if key == nil {
		return fmt.Errorf("error unsealing vault (100)") //no unsealer key provided
	}

	// we can't unseal an unsealed application
	if UnsealerKey != nil {
		return fmt.Errorf("error unsealing vault (109)") //application already unsealed
	}

	// get the SHA512 hash of the generated unsealerkey
	incomingKeyHash := crypto.SHA512.New()
	_, err := incomingKeyHash.Write(*key)
	if err != nil {
		return fmt.Errorf("error unsealing vault (200)") //error hashing incoming key
	}
	//incomingKeyHashHex := hex.EncodeToString(incomingKeyHash.Sum(nil))

	// TODO why is this always tripping...
	// if common.UnsealerKeyValidator == nil {
	// 	return fmt.Errorf("error unsealing vault (300)") //no unsealer validator set
	// }

	//check the unsealer key against the validation hash
	if common.UnsealerKeyValidator != nil {
		res := bytes.Compare(incomingKeyHash.Sum(nil), common.UnsealerKeyValidator[:])
		if res != 0 {
			return fmt.Errorf("error unsealing vault (400)") //unsealer key provided doesn't match validator hash
		}
	}

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault (500)") //error setting up cloaking key
	}

	// set the cloaking key to this random key
	CloakingKey = randomKey

	// conver the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = &randomKey

	// get the entropy from the seed phrase - we will use this as the AES encryption key for the vaults
	unsealerKeySeed, err := vaultcrypto.GetEntropyFromMnemonic(string(*key))
	if err != nil {
		return fmt.Errorf("error unsealing vault (550)")
	}

	common.Log.Debugf("unsealerKeySeed length: %d", len(unsealerKeySeed))
	common.Log.Debugf("unsealerkeyseed %s", string(unsealerKeySeed))
	common.Log.Debugf("mnemonic used %s", string(*key))
	// encrypt the unsealer key with the cloaking key
	unsealerKey, err := cloakingKey.Encrypt(unsealerKeySeed[0:32], nil) //HACK YBACKY
	if err != nil {
		return fmt.Errorf("error unsealing vault (600)") //error encrypting unsealer key with cloaking key
	}

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

	common.Log.Debugf("here sealing, sealerKey length: %d", len(*sealerKey.PrivateKey))
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

	// unsealerKey, err := vaultcrypto.CreateAES256GCMSeed()
	// if err != nil {
	// 	return nil, err
	// }

	// get the SHA512 hash of the generated unsealerkey
	validationHash := crypto.SHA512.New()
	_, err = validationHash.Write([]byte(*seedKey))
	if err != nil {
		return nil, err
	}

	response := NewUnsealerKeyResponse{}
	//key := common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(unsealerKey)))

	hash := common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(validationHash.Sum(nil))))
	response.UnsealerKey = &seedPhrase
	response.ValidationHash = hash

	return &response, nil
}

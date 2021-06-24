// +build unit

package test

import (
	"crypto"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
	"github.com/provideplatform/vault/vault"
	"github.com/tyler-smith/go-bip39"
)

var sealerDB = dbconf.DatabaseConnection()

var unsealerKey = "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day"

func unsealVault() {
	_ = vault.SetUnsealerKey(unsealerKey)
}

func setValidationHash(hash string) {
	os.Setenv("SEAL_UNSEAL_VALIDATION_HASH", hash)
}

func TestVaultUnseal(t *testing.T) {
	// seal the vault
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	err = vault.SetUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("failed to unseal vault: %s", err.Error())
		return
	}
}

func TestVaultUnsealNoUnsealerPhrase(t *testing.T) {
	defer unsealVault()
	// seal the vault
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	err = vault.SetUnsealerKey("")
	if err == nil {
		t.Errorf("unsealed vault with no key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealSealedVault(t *testing.T) {
	err := vault.SetUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error unsealing unsealed vault")
		return
	}
}

func TestUnsealNoValidationHash(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	hash := os.Getenv("SEAL_UNSEAL_VALIDATION_HASH")
	defer setValidationHash(hash)

	setValidationHash("")
	err = vault.SetUnsealerKey(unsealerKey)
	if err == nil {
		t.Errorf("unsealed vault without validation hash")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealIncorrectKey(t *testing.T) {
	defer unsealVault()
	// seal the vault
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	err = vault.SetUnsealerKey("incorrect value")
	if err == nil {
		t.Errorf("unsealed vault with incorrect unsealer key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealInvalidBIP39Phrase(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	hash := os.Getenv("SEAL_UNSEAL_VALIDATION_HASH")
	defer setValidationHash(hash)

	// set up bad data that will pass the validation, but fail to recover BIP39 entropy
	badKey, _ := common.RandomBytes(32)
	badHash := crypto.SHA256.New()
	_, _ = badHash.Write(badKey)
	os.Setenv("SEAL_UNSEAL_VALIDATION_HASH", hex.EncodeToString(badHash.Sum(nil)))

	err = vault.SetUnsealerKey(string(badKey))
	if err == nil {
		t.Errorf("unsealed vault with non-BIP39 key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealLowEntropyBIP39Phrase(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	hash := os.Getenv("SEAL_UNSEAL_VALIDATION_HASH")
	defer setValidationHash(hash)

	badEntropy, _ := bip39.NewEntropy(128)
	badMnemonic, _ := bip39.NewMnemonic(badEntropy)
	badHash := crypto.SHA256.New()
	_, _ = badHash.Write([]byte(badMnemonic))
	os.Setenv("SEAL_UNSEAL_VALIDATION_HASH", hex.EncodeToString(badHash.Sum(nil)))

	err = vault.SetUnsealerKey(badMnemonic)
	if err == nil {
		t.Errorf("unsealed vault with low-entropy BIP39 key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestCreateUnsealer(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	hash := os.Getenv("SEAL_UNSEAL_VALIDATION_HASH")
	defer setValidationHash(hash)

	// first we will create a new unsealer key & hash
	response, _ := vault.CreateUnsealerKey()
	unsealerKey := response.UnsealerKey
	validationHash := response.ValidationHash
	t.Logf("unsealer key: %s", *unsealerKey)
	t.Logf("validation hash: %s", *validationHash)

	// then we will use these to seal a vault
	setValidationHash(strings.Replace(*validationHash, "0x", "", -1))
	err = vault.SetUnsealerKey(*unsealerKey)
	if err != nil {
		t.Errorf("error unsealing vault with created key, error: %s", err.Error())
		return
	}
}

func TestCreateUnsealerAndSignVerify(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	err := vault.ClearUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("error sealing vault: %s", err.Error())
		return
	}

	hash := os.Getenv("SEAL_UNSEAL_VALIDATION_HASH")
	defer setValidationHash(hash)

	// first we will create a new unsealer key & hash
	response, _ := vault.CreateUnsealerKey()
	unsealerKey := response.UnsealerKey
	validationHash := response.ValidationHash
	t.Logf("unsealer key: %s", *unsealerKey)
	t.Logf("validation hash: %s", *validationHash)

	// then we will use these to seal a vault
	setValidationHash(strings.Replace(*validationHash, "0x", "", -1))
	err = vault.SetUnsealerKey(*unsealerKey)
	if err != nil {
		t.Errorf("error unsealing vault with created key")
		return
	}

	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(sealerDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, nil)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

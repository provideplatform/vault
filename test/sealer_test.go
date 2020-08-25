// +build unit

package test

import (
	"crypto"
	"encoding/hex"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
	"github.com/tyler-smith/go-bip39"
)

var sealerDB = dbconf.DatabaseConnection()

var unsealerKey = "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day"

func unsealVault() {
	_ = vault.SetUnsealerKey(unsealerKey)
}

func setValidationHash(hash string) {
	common.UnsealerKeyValidator = hash
}

func TestVaultUnseal(t *testing.T) {
	// seal the vault
	vault.UnsealerKey = nil
	err := vault.SetUnsealerKey(unsealerKey)
	if err != nil {
		t.Errorf("failed to unseal vault")
		return
	}
}

func TestVaultUnsealNoUnsealerPhrase(t *testing.T) {
	defer unsealVault()
	// seal the vault
	vault.UnsealerKey = nil

	err := vault.SetUnsealerKey("")
	if err == nil {
		t.Errorf("unsealed vault with no key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealSealedVault(t *testing.T) {
	err := vault.SetUnsealerKey(unsealerKey)
	if err == nil {
		t.Errorf("unsealed sealed vault")
		return
	}
}

func TestUnsealVaultNoValidationHash(t *testing.T) {
	hash := common.UnsealerKeyValidator
	defer setValidationHash(hash)

	common.UnsealerKeyValidator = ""
	err := vault.SetUnsealerKey(unsealerKey)
	if err == nil {
		t.Errorf("unsealed vault without validation hash")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealVaultIncorrectKey(t *testing.T) {
	defer unsealVault()
	// seal the vault
	vault.UnsealerKey = nil

	err := vault.SetUnsealerKey("incorrect value")
	if err == nil {
		t.Errorf("unsealed vault with incorrect unsealer key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealVaultInvalidBIP39Phrase(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	vault.UnsealerKey = nil
	hash := common.UnsealerKeyValidator
	defer setValidationHash(hash)

	// set up bad data that will pass the validation, but fail to recover BIP39 entropy
	badKey, _ := common.RandomBytes(32)
	badHash := crypto.SHA256.New()
	_, _ = badHash.Write(badKey)
	common.UnsealerKeyValidator = hex.EncodeToString(badHash.Sum(nil))

	err := vault.SetUnsealerKey(string(badKey))
	if err == nil {
		t.Errorf("unsealed vault with non-BIP39 key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

func TestUnsealVaultLowEntropyBIP39Phrase(t *testing.T) {
	//correct everything after test
	defer unsealVault()
	vault.UnsealerKey = nil
	hash := common.UnsealerKeyValidator
	defer setValidationHash(hash)

	badEntropy, _ := bip39.NewEntropy(128)
	badMnemonic, _ := bip39.NewMnemonic(badEntropy)
	badHash := crypto.SHA256.New()
	_, _ = badHash.Write([]byte(badMnemonic))
	common.UnsealerKeyValidator = hex.EncodeToString(badHash.Sum(nil))

	err := vault.SetUnsealerKey(badMnemonic)
	if err == nil {
		t.Errorf("unsealed vault with low-entropy BIP39 key")
		return
	}
	t.Logf("error received: %s", err.Error())
}

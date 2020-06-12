package vault

import (
	"fmt"
	"testing"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
)

var keyDB = dbconf.DatabaseConnection()

func vaultFactory() *Vault {
	vault := &Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil(fmt.Sprintf("vault@%d", time.Now().Unix())),
		Description:    common.StringOrNil("a test vault for key unit tests"),
	}

	vault.Create(vaultDB)
	return vault
}

func TestCreateKeyAES256GCM(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key create unit test!")
		return
	}

	// TODO!
	// key, err := vault.CreateAES256GCMKey(keyDB)

	// success := err == nil && key != nil && key.ID != uuid.Nil
	// if !success {
	// 	t.Errorf("failed to create AES-256-GCM key for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created AES-256-GCM key for vault: %s", vault.ID)
}

func TestCreateKeyChaCha20(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for ChaCha20 key create unit test!")
		return
	}

	// TODO!
	// key, err := vault.CreateChaCha20Key(keyDB)

	// success := err == nil && key != nil && key.ID != uuid.Nil
	// if !success {
	// 	t.Errorf("failed to create ChaCha20 key for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created ChaCha20 key for vault: %s", vault.ID)
}

func TestCreateKeyBabyJubJub(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key create unit test!")
		return
	}

	// TODO!
	// key, err := vault.CreateBabyJubJubKeypair(keyDB)

	// success := err == nil && key != nil && key.ID != uuid.Nil
	// if !success {
	// 	t.Errorf("failed to create babyJubJub keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created babyJubJub keypair for vault: %s", vault.ID)
}

func TestCreateKeyC25519(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for C25519 key create unit test!")
		return
	}

	// TODO!
	// key, err := vault.CreateC25519Keypair(keyDB)

	// success := err == nil && key != nil && key.ID != uuid.Nil
	// if !success {
	// 	t.Errorf("failed to create C25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created C25519 keypair for vault: %s", vault.ID)
}

func TestCreateKeyEd25519(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key create unit test!")
		return
	}

	// TODO!
	// key, err := vault.CreateEd25519Keypair(keyDB)

	// success := err == nil && key != nil && key.ID != uuid.Nil
	// if !success {
	// 	t.Errorf("failed to create Ed25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created Ed25519 keypair for vault: %s", vault.ID)
}

func TestCreateKeySecp256k1(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key create unit test!")
		return
	}

	// TODO!
	// key, err := vault.CreateSecp256k1Keypair(keyDB)

	// success := err == nil && key != nil && key.ID != uuid.Nil
	// if !success {
	// 	t.Errorf("failed to create secp256k1 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created secp256k1 keypair for vault: %s", vault.ID)
}

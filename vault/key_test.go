package vault

import (
	"fmt"
	"testing"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
)

var db = dbconf.DatabaseConnection()

func vaultFactory() *Vault {
	vault := &Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil(fmt.Sprintf("vault@%d", time.Now().Unix())),
		Description:    common.StringOrNil("a test vault for key unit tests"),
	}

	vault.Create(db)
	return vault
}

func TestCreateKeyAES256GCM(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key create unit test!")
		return
	}

	// TODO!
	// key := vault.CreateAES256GCMKey()

	// success := key.Create(db)
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
	// key := vault.CreateChaCha20Key()

	// success := key.Create(db)
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
	// key := vault.CreateBabyJubJubKeypair()

	// success := key.Create(db)
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
	// key := vault.CreateC25519Keypair()

	// success := key.Create(db)
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
	// key := vault.CreateEd25519Keypair()

	// success := key.Create(db)
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
	// key := vault.CreateSecp256k1Keypair()

	// success := key.Create(db)
	// if !success {
	// 	t.Errorf("failed to create secp256k1 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
	// 	return
	// }

	// common.Log.Debugf("created secp256k1 keypair for vault: %s", vault.ID)
}

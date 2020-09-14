// +build unit

package test

import (
	"encoding/hex"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

var edKeyDB = dbconf.DatabaseConnection()

func TestCreateKeyEd25519(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key create unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	// it should have a private key
	seed := key.Seed
	if seed == nil {
		t.Error("failed! seed was not set for the Ed25519 key!")
		return
	}
	// it should have a public key
	publicKey := key.PublicKey
	if publicKey == nil {
		t.Error("failed! public key was not set for the Ed25519 key!")
		return
	}

	common.Log.Debugf("created Ed25519 keypair for vault: %s", vlt.ID)
}

func TestVerifyEd25519NilPublicKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("error signing message using ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	key.PublicKey = nil
	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using Ed25519 keypair with nil publickey for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestVerifyEd25519InvalidSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("error signing message using ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	invalidSpec := "non-existent key"
	key.Spec = &invalidSpec
	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using Ed25519 keypair with invalid spec for vault: %s; err: %s", vlt.ID, err.Error())
}

func TestVerifyEd25519NilSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("error signing message using ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	key.Spec = nil
	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using Ed25519 keypair with nil spec for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSignEd25519NilSeed(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	key.Seed = nil
	_, err = key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message using Ed25519 keypair with nil seed for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with ed25519 key with no seed")
	}
}

func TestEd25519Sign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	common.Log.Debugf("signed message using Ed25519 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestEd25519Verify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key verify unit test!")
		return
	}

	key, err := vault.Ed25519Factory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	err = key.Verify(msg, sig, nil)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using Ed25519 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

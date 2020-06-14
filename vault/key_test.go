package vault

import (
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	keytestpgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
)

func init() {
	keytestpgputil.RequirePGP()
}

var keyDB = dbconf.DatabaseConnection()

func aes256GCMFactory(vaultID *uuid.UUID) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil("AES-256-GCM key test"),
		Description: common.StringOrNil("some AES-256-GCM test key"),
		Spec:        common.StringOrNil(keySpecAES256GCM),
		Type:        common.StringOrNil(keyTypeSymmetric),
		Usage:       common.StringOrNil(keyUsageEncryptDecrypt),
	}

	if !key.createPersisted(keyDB) {
		return nil
	}

	return key
}

func babyJubJubFactory(vaultID *uuid.UUID) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil("babyJubJub key test"),
		Description: common.StringOrNil("some babyJubJub test key"),
		Spec:        common.StringOrNil(keySpecECCBabyJubJub),
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
	}

	if !key.createPersisted(keyDB) {
		return nil
	}

	return key
}

func c25519Factory(vaultID *uuid.UUID) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil("C25519 key test"),
		Description: common.StringOrNil("some C25519 test key"),
		Spec:        common.StringOrNil(keySpecECCC25519),
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
	}

	if !key.createPersisted(keyDB) {
		return nil
	}

	return key
}

func chacha20Factory(vaultID *uuid.UUID) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil("ChaCha20 key test"),
		Description: common.StringOrNil("some ChaCha20 test key"),
		Spec:        common.StringOrNil(keySpecChaCha20),
		Type:        common.StringOrNil(keyTypeSymmetric),
		Usage:       common.StringOrNil(keyUsageEncryptDecrypt),
	}

	if !key.createPersisted(keyDB) {
		return nil
	}

	return key
}

func ed25519Factory(vaultID *uuid.UUID) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil("Ed25519 key test"),
		Description: common.StringOrNil("some Ed25519 test key"),
		Spec:        common.StringOrNil(keySpecECCEd25519),
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
	}

	if !key.createPersisted(keyDB) {
		return nil
	}

	return key
}

func secp256k1Factory(vaultID *uuid.UUID) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil("secp256k1 key test"),
		Description: common.StringOrNil("some secp256k1 test key"),
		Spec:        common.StringOrNil(keySpecECCSecp256k1),
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
	}

	if !key.createPersisted(keyDB) {
		return nil
	}

	return key
}

func TestEncryptAndDecrypt(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key encrypt decrypt unit test!")
		return
	}

	t.Error("encrypt/decrypt key tests not implemented")
}

func TestCreateKeyAES256GCM(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key create unit test!")
		return
	}

	key := aes256GCMFactory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	common.Log.Debugf("created AES-256-GCM key for vault: %s", vault.ID)
}

func TestCreateKeyBabyJubJub(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key create unit test!")
		return
	}

	key := babyJubJubFactory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create babyJubJub keypair for vault: %s!", vault.ID)
		return
	}

	common.Log.Debugf("created babyJubJub keypair for vault: %s", vault.ID)
}

func TestCreateKeyC25519(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for C25519 key create unit test!")
		return
	}

	key := c25519Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create C25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	common.Log.Debugf("created C25519 keypair for vault: %s", vault.ID)
}

func TestCreateKeyChaCha20(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for ChaCha20 key create unit test!")
		return
	}

	key := chacha20Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create ChaCha20 key for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	common.Log.Debugf("created ChaCha20 key for vault: %s", vault.ID)
}

func TestCreateKeyEd25519(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key create unit test!")
		return
	}

	key := ed25519Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	common.Log.Debugf("created Ed25519 keypair for vault: %s", vault.ID)
}

func TestCreateKeySecp256k1(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key create unit test!")
		return
	}

	key := secp256k1Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	common.Log.Debugf("created secp256k1 keypair for vault: %s", vault.ID)
}

func TestBabyJubJubSign(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key signing unit test!")
		return
	}

	key := babyJubJubFactory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create babyJubJub keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using babyJubJub keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using babyJubJub keypair for vault: %s! nil signature!", vault.ID)
		return
	}

	// if len(sig) != 64 {
	// 	t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
	// 	return
	// }

	common.Log.Debugf("signed message using babyJubJub keypair for vault: %s; sig: %s", vault.ID, string(sig))
}

func TestEd25519Sign(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key signing unit test!")
		return
	}

	key := ed25519Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! nil signature!", vault.ID)
		return
	}

	// if len(sig) != 64 {
	// 	t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
	// 	return
	// }

	common.Log.Debugf("signed message using Ed25519 keypair for vault: %s; sig: %s", vault.ID, string(sig))
}

func TestEd25519Verify(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key verify unit test!")
		return
	}

	key := ed25519Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! nil signature!", vault.ID)
		return
	}

	// if len(sig) != 64 {
	// 	t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
	// 	return
	// }

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using Ed25519 keypair for vault: %s; sig: %s", vault.ID, string(sig))
}

func TestSecp256k1Sign(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key signing unit test!")
		return
	}

	key := secp256k1Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s! nil signature!", vault.ID)
		return
	}

	// if len(sig) != 64 {
	// 	t.Errorf("failed to sign message using secp256k1 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
	// 	return
	// }

	common.Log.Debugf("signed message using secp256k1 keypair for vault: %s; sig: %s", vault.ID, string(sig))
}

func TestSecp256k1Verify(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key := secp256k1Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s! nil signature!", vault.ID)
		return
	}

	// if len(sig) != 64 {
	// 	t.Errorf("failed to sign message using secp256k1 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
	// 	return
	// }

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using secp256k1 keypair for vault: %s; sig: %s", vault.ID, string(sig))
}

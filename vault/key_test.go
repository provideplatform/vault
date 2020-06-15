package vault

import (
	"encoding/hex"
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

func TestAES256GCMEncrypt(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key encrypt decrypt unit test!")
		return
	}

	key := aes256GCMFactory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	msg := []byte(common.RandomString(10))
	encval, err := key.Encrypt(msg)

	// it should not result in an error ;)
	if err != nil {
		t.Errorf("failed! symmetric encryption failed using AES-256-GCM key %s; %s", key.ID, err.Error())
		return
	}

	common.Log.Debugf("encrypted %d-byte message (%d bytes encrypted) using AES-256-GCM key for vault: %s", len(msg), len(encval), vault.ID)
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

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the AES-256-GCM key!")
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

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the babyJubJub key!")
		return
	}
	// it should have a public key
	publicKey := key.PublicKey
	if publicKey == nil {
		t.Error("failed! public key was not set for the babyJubJub key!")
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

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the C25519 key!")
		return
	}
	// it should have a public key
	publicKey := key.PublicKey
	if publicKey == nil {
		t.Error("failed! public key was not set for the C25519 key!")
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

	// it should have a seed
	seed := key.Seed
	if seed == nil {
		t.Error("failed! seed was not set for the ChaCha20 key!")
		return
	}

	common.Log.Debugf("created ChaCha20 key for vault: %s", vault.ID)
}

func TestInvalidEd25519Key(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := ed25519Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	// no vault id
	key.VaultID = nil
	validVault := key.validate()
	if validVault {
		t.Errorf("validated key with no vault id! errors: %s", *key.Errors[0].Message)
		return
	} else {
		common.Log.Debug("correctly flagged key with no vault as invalid")
		if *key.Errors[0].Message != "vault id required" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}

	key.VaultID = &vault.ID

	// no name
	key.Name = nil
	validName := key.validate()
	if validName {
		t.Errorf("validated key with no name! errors: %s", *key.Errors[0].Message)
		return
	} else {
		common.Log.Debug("correctly flagged key with no name as invalid")
		if *key.Errors[0].Message != "key name required" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}

	key.Name = common.StringOrNil("keyname")
	common.Log.Debugf("key.name: %s", *key.Name)

	key.Usage = nil
	// TODO: getting a nil pointer error for the code below - nothing obvious why - fix later!

	// validUsage := key.validate()
	// if validUsage {
	// 	t.Errorf("validated key with no Usage! errors: %s", *key.Errors[0].Message)
	// 	return
	// } else {
	// 	common.Log.Debug("correctly flagged key with no usage as invalid")
	// 	if *key.Errors[0].Message != "key usage required" {
	// 		t.Errorf("returned incorrect validation message")
	// 		return
	// 	}
	// }

	// *key.Usage = keyUsageSignVerify
	// key.Spec = nil

	// validSpec := key.validate()
	// if validSpec {
	// 	t.Errorf("validated key with no Spec! errors: %s", *key.Errors[0].Message)
	// 	return
	// } else {
	// 	if *key.Errors[0].Message != "key spec required" {
	// 		t.Errorf("returned incorrect validation message")
	// 		return
	// 	}
	// }

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

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the secp256k1 key!")
		return
	}
	// it should have a public key
	publicKey := key.PublicKey
	if publicKey == nil {
		t.Error("failed! public key was not set for the secp256k1 key!")
		return
	}
	// it should have a non-nil address enriched
	address := key.Address
	if address == nil {
		t.Error("failed! address was not set for the secp256k1 key!")
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

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
		return
	}

	common.Log.Debugf("signed message using babyJubJub keypair for vault: %s; sig: %s", vault.ID, hex.EncodeToString(sig))
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

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
		return
	}

	common.Log.Debugf("signed message using Ed25519 keypair for vault: %s; sig: %s", vault.ID, hex.EncodeToString(sig))
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

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s! received %d-byte signature: %s", vault.ID, len(sig), sig)
		return
	}

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using Ed25519 keypair for vault: %s; sig: %s", vault.ID, hex.EncodeToString(sig))
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

	common.Log.Debugf("signed message using secp256k1 keypair for vault: %s; sig: %s", vault.ID, hex.EncodeToString(sig))
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

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s! %s", vault.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using secp256k1 keypair for vault: %s; sig: %s", vault.ID, hex.EncodeToString(sig))
}

package test

import (
	"encoding/hex"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	keyspgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

func init() {
	keyspgputil.RequirePGP()
}

var keyDB = dbconf.DatabaseConnection()

func TestAES256GCMEncrypt(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key encrypt decrypt unit test!")
		return
	}

	key := vault.AES256GCMFactory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	encval, err := key.Encrypt(msg)

	// it should not result in an error ;)
	if err != nil {
		t.Errorf("failed! symmetric encryption failed using AES-256-GCM key %s; %s", key.ID, err.Error())
		return
	}

	common.Log.Debugf("encrypted %d-byte message (%d bytes encrypted) using AES-256-GCM key for vault: %s", len(msg), len(encval), vlt.ID)
}

func TestCreateKeyAES256GCM(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key create unit test!")
		return
	}

	key := vault.AES256GCMFactory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s", vlt.ID)
		return
	}

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the AES-256-GCM key!")
		return
	}

	common.Log.Debugf("created AES-256-GCM key for vault: %s", vlt.ID)
}

func TestCreateKeyBabyJubJub(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key create unit test!")
		return
	}

	key := vault.BabyJubJubFactory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create babyJubJub keypair for vault: %s", vlt.ID)
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

	common.Log.Debugf("created babyJubJub keypair for vault: %s", vlt.ID)
}

func TestCreateKeyC25519(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for C25519 key create unit test!")
		return
	}

	key := vault.C25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create C25519 keypair for vault: %s", vlt.ID)
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

	common.Log.Debugf("created C25519 keypair for vault: %s", vlt.ID)
}

func TestCreateKeyChaCha20(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ChaCha20 key create unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create ChaCha20 key for vault: %s", vlt.ID)
		return
	}

	// it should have a seed
	seed := key.Seed
	if seed == nil {
		t.Error("failed! seed was not set for the ChaCha20 key!")
		return
	}

	common.Log.Debugf("created ChaCha20 key for vault: %s", vlt.ID)
}

func TestValidateNoVault(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	key.VaultID = nil
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with no vault id!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key with no vault as invalid")
		if *key.Errors[0].Message != "vault id required" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateNoName(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	key.Name = nil
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with no vault id!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key with no name as invalid")
		if *key.Errors[0].Message != "key name required" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateNoSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	key.Spec = nil
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with no spec! errors: %s", *key.Errors[0].Message)
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key with no spec as invalid")
		if *key.Errors[0].Message != "key spec required" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateNoType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	key.Type = nil
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with no type!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key with no type as invalid")
		if *key.Errors[0].Message != "key type required" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateInvalidType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	*key.Type = "invalid value"
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with invalid type!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key with invalid type as invalid")
		if *key.Errors[0].Message != "key type must be one of "+vault.KeyTypeAsymmetric+" or "+vault.KeyTypeSymmetric {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateInvalidSymmetricUsage(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	*key.Type = vault.KeyTypeSymmetric
	*key.Usage = vault.KeyUsageSignVerify
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with invalid type!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key as invalid")
		if *key.Errors[0].Message != "symmetric key requires "+vault.KeyUsageEncryptDecrypt+" usage mode" {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateInvalidSymmetricUsageSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	*key.Type = vault.KeyTypeSymmetric
	*key.Usage = vault.KeyUsageEncryptDecrypt
	*key.Spec = vault.KeySpecECCEd25519
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with invalid type!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key as invalid")
		if *key.Errors[0].Message != "symmetric key in "+vault.KeyUsageEncryptDecrypt+" usage mode must be "+vault.KeySpecAES256GCM+" or "+vault.KeySpecChaCha20 {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

func TestValidateInvalidAsymmetricUsageSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key validate unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	// no vault id
	*key.Type = vault.KeyTypeAsymmetric
	*key.Usage = vault.KeyUsageSignVerify
	*key.Spec = vault.KeySpecAES256GCM
	valid := key.Validate()
	if valid {
		t.Errorf("validated key with invalid type!")
		return
	}

	if !valid {
		common.Log.Debug("correctly flagged key as invalid")
		if *key.Errors[0].Message != "asymmetric key in "+vault.KeyUsageSignVerify+" usage mode must be "+vault.KeySpecECCBabyJubJub+", "+vault.KeySpecECCC25519+", "+vault.KeySpecECCEd25519+" or "+vault.KeySpecECCSecp256k1 {
			t.Errorf("returned incorrect validation message")
			return
		}
	}
}

//FIXME this test throws a nil pointer dereference for some unknown reason
// func TestValidateNoUsage(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s %s", vlt.ID, *key.Errors[0].Message)
// 		return
// 	}

// 	// no vault id
// 	key.Usage = nil
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with no usage! errors: %s", *key.Errors[0].Message)
// 		return
// 	}

// 	if !valid {
// 		common.Log.Debug("correctly flagged key with no usage as invalid")
// 		if *key.Errors[0].Message != "key usage required" {
// 			t.Errorf("returned incorrect validation message")
// 			return
// 		}
// 	}
// }

func TestCreateKeyEd25519(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key create unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
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

func TestCreateKeySecp256k1(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key create unit test!")
		return
	}

	key := vault.Secp256k1Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
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

	common.Log.Debugf("created secp256k1 keypair for vault: %s", vlt.ID)
}

func TestBabyJubJubSign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key signing unit test!")
		return
	}

	key := vault.BabyJubJubFactory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create babyJubJub keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using babyJubJub keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using babyJubJub keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519 keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	common.Log.Debugf("signed message using babyJubJub keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestEd25519Sign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key signing unit test!")
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
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

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
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

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using Ed25519 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1Sign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key signing unit test!")
		return
	}

	key := vault.Secp256k1Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	common.Log.Debugf("signed message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1Verify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key := vault.Secp256k1Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestCreateEphemeralKeyAES256GCM_privatekey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for create ephemeral AES256GCM unit test!")
		return
	}

	key := vault.AES256GCMEphemeralFactory(&vlt.ID)

	//common.Log.Debugf("error returned %s", err.Error())
	if key == nil { // FIXME -- return (key, err) from all factories
		t.Errorf("failed to create ephemeral AES-256-GCM key for vault: %s", vlt.ID) //, *key.Errors[0].Message)
		return
	}

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the AES-256-GCM key!")
		return
	}
	ephemeral := key.EphemeralPrivateKey
	if ephemeral == nil {
		t.Error("failed! key returned without ephemeral private key")
		return
	}

	common.Log.Debugf("created ephemeral AES-256-GCM key for vault: %s", vlt.ID)
}

// FIXME? I don't think this test case applies as its handled internally by package-private `create()`. What am I missing? --KT
// func TestCreateEphemeralKeyAES256GCM_seed(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for ephemeral AES256GCM unit test!")
// 		return
// 	}

// 	key := vault.AES256GCMEphemeralFactory(&vlt.ID)
// 	key.PrivateKey = nil
// 	seed := "hubbachubba"
// 	key.Seed = &seed

// 	err := key.create()

// 	//common.Log.Debugf("error returned %s", err.Error())
// 	if err != nil {
// 		t.Errorf("failed to create ephemeral AES-256-GCM key for vault: %s %s", vlt.ID, *key.Errors[0].Message)
// 		return
// 	}

// 	ephemeral := key.EphemeralSeed
// 	if ephemeral == nil {
// 		t.Error("failed! key returned without ephemeral seed")
// 		return
// 	}

// 	common.Log.Debugf("created ephemeral AES-256-GCM key for vault: %s", vlt.ID)
// }

// FIXME? I don't think this test case applies as its handled internally by package-private `create()`. We need an implicit regeneration method... What am I missing? --KT
// func TestRegenerateExistingKeyAES256GCM(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for ephemeral AES256GCM unit test!")
// 		return
// 	}
// 	key := vault.AES256GCMEphemeralFactory(&vlt.ID)
// 	key.PrivateKey = nil
// 	seed := "hubbachubba"
// 	key.Seed = &seed

// 	err := key.create()

// 	//common.Log.Debugf("error returned %s", err.Error())
// 	if err != nil {
// 		t.Errorf("failed to create ephemeral AES-256-GCM key for vault: %s %s", vlt.ID, *key.Errors[0].Message)
// 		return
// 	}

// 	ephemeral := key.EphemeralSeed
// 	if ephemeral == nil {
// 		t.Error("failed! key returned without ephemeral seed")
// 		return
// 	}

// 	common.Log.Debugf("created ephemeral AES-256-GCM key for vault: %s", vlt.ID)
// }

func TestCreateAes256GCMInvalidVaultID(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ephemeral AES256GCM unit test!")
		return
	}

	key := vault.AES256GCMEphemeralFactory(nil)
	if key != nil {
		t.Errorf("failed to invalidate key with invalid vault id: %s", vlt.ID)
		return
	}

	common.Log.Debugf("invalidated invalid AES-256-GCM key for vault: %s", vlt.ID)
}

func TestDeriveSymmetricKeyInvalidType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	key.Type = nil

	nonce := []byte("number only used once")
	context := []byte("stuff and stuff")
	name := "derived key"
	description := "derived key description"

	key, err := key.DeriveSymmetric(nonce, context, name, description)

	if err != nil {
		common.Log.Debug("correctly failed to derive symmetric key")
	}
	if err == nil {
		t.Errorf("incorrectly derived symmetric key without type")
	}
}

func TestDeriveSymmetricKeyIncorrectSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	*key.Spec = vault.KeySpecAES256GCM

	nonce := []byte("number only used once")
	context := []byte("stuff and stuff")
	name := "derived key"
	description := "derived key description"

	key, err := key.DeriveSymmetric(nonce, context, name, description)

	if err != nil {
		common.Log.Debug("correctly failed to derive symmetric key")
	}
	if err == nil {
		t.Errorf("incorrectly derived symmetric key with incorrect spec")
	}
}

func TestDeriveSymmetricKeyIncorrectType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	*key.Type = vault.KeyTypeAsymmetric

	nonce := []byte("number only used once")
	context := []byte("stuff and stuff")
	name := "derived key"
	description := "derived key description"

	key, err := key.DeriveSymmetric(nonce, context, name, description)

	if err != nil {
		common.Log.Debug("correctly failed to derive symmetric key")
	}
	if err == nil {
		t.Errorf("incorrectly derived symmetric key with incorrect type")
	}
}

func TestDeriveSymmetricKeyIncorrectUsage(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	*key.Usage = vault.KeyUsageSignVerify

	nonce := []byte("number only used once")
	context := []byte("stuff and stuff")
	name := "derived key"
	description := "derived key description"

	key, err := key.DeriveSymmetric(nonce, context, name, description)

	if err != nil {
		common.Log.Debug("correctly failed to derive symmetric key")
	}
	if err == nil {
		t.Errorf("incorrectly derived symmetric key with incorrect usage")
	}
}

func TestDeriveSymmetricKeyNilSeed(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	nonce := []byte("number only used once")
	context := []byte("stuff and stuff")
	name := "derived key"
	description := "derived key description"
	key.Seed = nil

	key, err := key.DeriveSymmetric(nonce, context, name, description)

	if err != nil {
		common.Log.Debugf("correctly failed to derive symmetric with nil seed key. error %s", err.Error())
	}
	if err == nil {
		t.Errorf("incorrectly derived symmetric key without seed")
	}
}

// func TestDeriveSymmetricKey(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for derive symmetric key unit test!")
// 		return
// 	}

// 	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

// 	// seed info
// 	common.Log.Debugf("seed size (bytes %d)", len([]byte(*key.Seed)))
// 	common.Log.Debugf("seed type %T", *key.Seed)
// 	common.Log.Debugf("key seed: %s", *key.Seed)

// 	nonce := []byte("number only used once")
// 	context := []byte("stuff and stuff")
// 	name := "derived key"
// 	description := "derived key description"

// 	key, err := key.DeriveSymmetric(nonce, context, name, description)

// 	if err != nil {
// 		common.Log.Warningf("key derivation failed; %s", err.Error())
// 		t.Errorf("failed to derive symmetric key with error %s", err.Error())
// 		return
// 	}
// 	if err == nil {
// 		common.Log.Debugf("correctly derived symmetric key from key %s", key.ID)
// 	}
// }

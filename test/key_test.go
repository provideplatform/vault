// +build unit

package test

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

var keyDB = dbconf.DatabaseConnection()
var NonceSizeSymmetric = 12

func TestChaCha20EncryptShortNonce(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for chacha20 key encrypt decrypt unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create chacha20 key for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	nonce := []byte(common.RandomString(2))
	_, err := key.Encrypt(msg, nonce)

	if err != nil {
		t.Errorf("failed! symmetric encryption failed using chacha20 key %s; %s", key.ID, err.Error())
		return
	}
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
		t.Error("validated key with no spec! errors")
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

// func TestValidateNoType(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
// 		return
// 	}

// 	// no vault id
// 	key.Type = nil
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with no type!")
// 		return
// 	}

// 	if !valid {
// 		common.Log.Debug("correctly flagged key with no type as invalid")
// 		if *key.Errors[0].Message != "key type required" {
// 			t.Errorf("returned incorrect validation message")
// 			return
// 		}
// 	}
// }

// can't test nil usage properly as it's dereferenced later in function and throws a nill pointer exception
// maybe try to recover?
// func TestValidateNoUsage(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
// 		return
// 	}

// 	// no vault id
// 	key.Usage = common.StringOrNil("")
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with no usage!")
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

// func TestValidateInvalidType(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
// 		return
// 	}

// 	// no vault id
// 	*key.Type = "invalid value"
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with invalid type!")
// 		return
// 	}

// 	if !valid {
// 		common.Log.Debug("correctly flagged key with invalid type as invalid")
// 		if *key.Errors[0].Message != "key type must be one of "+vault.KeyTypeAsymmetric+" or "+vault.KeyTypeSymmetric {
// 			t.Errorf("returned incorrect validation message")
// 			return
// 		}
// 	}
// }

// func TestValidateInvalidSymmetricUsage(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
// 		return
// 	}

// 	// no vault id
// 	*key.Type = vault.KeyTypeSymmetric
// 	*key.Usage = vault.KeyUsageSignVerify
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with invalid type!")
// 		return
// 	}

// 	if !valid {
// 		common.Log.Debug("correctly flagged key as invalid")
// 		if *key.Errors[0].Message != fmt.Sprintf("symmetric key requires %s usage mode", vault.KeyUsageEncryptDecrypt) {
// 			t.Errorf("returned incorrect validation message")
// 			return
// 		}
// 	}
// }

// func TestValidateInvalidSymmetricUsageSpec(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
// 		return
// 	}

// 	// no vault id
// 	*key.Type = vault.KeyTypeSymmetric
// 	*key.Usage = vault.KeyUsageEncryptDecrypt
// 	*key.Spec = vault.KeySpecECCEd25519
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with invalid type!")
// 		return
// 	}

// 	if !valid {
// 		common.Log.Debug("correctly flagged key as invalid")
// 		if *key.Errors[0].Message != "symmetric key in "+vault.KeyUsageEncryptDecrypt+" usage mode must be "+vault.KeySpecAES256GCM+" or "+vault.KeySpecChaCha20 {
// 			t.Errorf("returned incorrect validation message")
// 			return
// 		}
// 	}
// }

// func TestValidateInvalidAsymmetricUsageSpec(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for Ed25519 key validate unit test!")
// 		return
// 	}

// 	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
// 	if key == nil {
// 		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
// 		return
// 	}

// 	// no vault id
// 	*key.Type = vault.KeyTypeAsymmetric
// 	*key.Usage = vault.KeyUsageSignVerify
// 	*key.Spec = vault.KeySpecAES256GCM
// 	valid := key.Validate()
// 	if valid {
// 		t.Errorf("validated key with invalid type!")
// 		return
// 	}

// 	if !valid {
// 		common.Log.Debug("correctly flagged key as invalid")
// 	}
// }

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

func TestDeriveSymmetricKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	// nonce is 16 bytes for derivation function
	nonce := []byte(common.RandomString(16))
	context := []byte("stuff and stuff")
	name := "derived key"
	description := "derived key description"

	key, err := key.DeriveSymmetric(nonce, context, name, description)

	if err != nil {
		common.Log.Warningf("key derivation failed; %s", err.Error())
		t.Errorf("failed to derive symmetric key with error %s", err.Error())
		return
	}
	if err == nil {
		common.Log.Debugf("correctly derived symmetric key from key %s", key.ID)
	}
}

func TestEncryptChaChaNoErrors(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	plaintext := []byte(common.RandomString(128))

	ciphertext, err := key.Encrypt(plaintext, nil)
	if err != nil {
		t.Errorf("failed to encrypt plaintext with error: %s", err.Error())
		return
	}

	nonceSize := 12
	if len(plaintext)+nonceSize != len(ciphertext) {
		t.Errorf("%d-byte ciphertext is not the same length as %d-byte plaintext", len(ciphertext)-nonceSize, len(plaintext))
		return
	}

	if err == nil {
		common.Log.Debug("encrypted with no errors")
	}

}

func TestEncryptChaChaNilKeyType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	plaintext := []byte(common.RandomString(128))

	key.Type = nil
	_, err := key.Encrypt(plaintext, nil)
	if err == nil {
		t.Error("failed to trap nil type on key")
		return
	}
}

func TestEncryptChaChaNilSeed(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	plaintext := []byte(common.RandomString(128))

	key.Seed = nil
	_, err := key.Encrypt(plaintext, nil)
	if err == nil {
		t.Error("failed to trap nil seed on key")
		return
	}
}

func TestEncryptAndDecryptSymmetricChaChaNoErrors(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	plaintext := []byte(common.RandomString(128))

	ciphertext, err := key.Encrypt(plaintext, nil)
	if err != nil {
		t.Errorf("failed to encrypt plaintext with error: %s", err.Error())
		return
	}

	if hex.EncodeToString(ciphertext[vault.NonceSizeSymmetric:]) == hex.EncodeToString(plaintext) {
		t.Error("encrypted text is the same as plaintext")
		return
	}

	if len(plaintext)+vault.NonceSizeSymmetric != len(ciphertext) {
		t.Errorf("%d-byte ciphertext is not the same length as %d-byte plaintext", len(ciphertext)-vault.NonceSizeSymmetric, len(plaintext))
		return
	}

	decryptedtext, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("failed to decrypt encrypted text  with error: %s", err.Error())
		return
	}

	if hex.EncodeToString(decryptedtext) != hex.EncodeToString(plaintext) {
		t.Error("decrypted text is not the same as original plaintext!")
		return
	}
	common.Log.Debug("decrypted ciphertext is identical to original plaintext")
}

func TestDeleteKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	deleted := key.Delete(keyDB)
	if !deleted {
		t.Errorf("couldn't delete key %s, error: %s", key.ID, *key.Errors[0].Message)
		return
	}
}

func TestECDH(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	// TODO add test for ephemeral
	// create the peer ecdh key
	peerECDHkey := vault.C25519Factory(keyDB, &vlt.ID, "ecdh public key", "test key")
	if peerECDHkey == nil {
		t.Error("peer ecdh key is nil after being created!")
	}

	//create my ecdh key
	myECDHkey := vault.C25519Factory(keyDB, &vlt.ID, "ecdh public key", "test key")
	if myECDHkey == nil {
		t.Error("my ecdh key is nil after being created!")
	}

	// create the peer signing key
	peerSigningkey := vault.Ed25519Factory(keyDB, &vlt.ID, "peer ecdh signing key", "test key")

	// sign the peer ecdh key with the peer signing key
	peerSignature, err := peerSigningkey.Sign([]byte(*peerECDHkey.PublicKey), nil)
	if err != nil {
		t.Errorf("got error signing peer c25519 public key. Error: %s", err.Error())
		return
	}

	//verify the peer signature worked ok
	err = peerSigningkey.Verify([]byte(*peerECDHkey.PublicKey), peerSignature, nil)
	if err != nil {
		t.Errorf("error validating peer signature %s", err.Error())
		return
	}
	if err == nil {
		common.Log.Debug("peer signature validated ok")
	}

	mySigningKey := vault.Ed25519Factory(keyDB, &vlt.ID, "my ecdh signing key", "test key")
	mySignature, err := mySigningKey.Sign([]byte(*myECDHkey.PublicKey), nil)
	if err != nil {
		t.Errorf("got error signing my c25519 public key. Error: %s", err.Error())
		return
	}

	//verify my signature worked ok
	err = mySigningKey.Verify([]byte(*myECDHkey.PublicKey), mySignature, nil)
	if err != nil {
		t.Errorf("error validating my signature %s", err.Error())
		return
	}
	if err == nil {
		common.Log.Debug("my signature validated ok")
	}

	// create the peer diffie hellman secret
	peerSecretKey, err := myECDHkey.CreateDiffieHellmanSharedSecret([]byte(*peerECDHkey.PublicKey), []byte(*peerSigningkey.PublicKey), peerSignature, "ecdh name", "ecdh description")
	if err != nil {
		t.Errorf("error creating my diffie hellman secret. Error: %s", err.Error())
		return
	}
	if err == nil {
		common.Log.Debugf("returned chacha20 key with ID %s", peerSecretKey.ID)
	}

	// create my diffie hellman secret
	mySecretKey, err := peerECDHkey.CreateDiffieHellmanSharedSecret([]byte(*myECDHkey.PublicKey), []byte(*mySigningKey.PublicKey), mySignature, "ecdh name", "ecdh description")
	if err != nil {
		t.Errorf("error creating peer diffie hellman secret. Error: %s", err.Error())
		return
	}
	if err == nil {
		common.Log.Debugf("returned chacha20 key with ID %s", mySecretKey.ID)
	}

	plaintext := common.RandomString(128)

	ciphertext, err := peerSecretKey.Encrypt([]byte(plaintext), nil)
	if err != nil {
		t.Errorf("error encrypting plaintext with peer key %s", err.Error())
		return
	}

	decryptedtext, err := mySecretKey.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("error decrypting ciphertext with my key %s", err.Error())
		return
	}

	if hex.EncodeToString(decryptedtext) != hex.EncodeToString([]byte(plaintext)) {
		t.Error("shared seed mismatch")
	}

	if hex.EncodeToString(decryptedtext) == hex.EncodeToString([]byte(plaintext)) {
		common.Log.Debug("successfully shared secret")
	}
}

func TestECDHNilPrivateKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	// TODO add test for ephemeral
	// create the peer ecdh key
	peerECDHkey := vault.C25519Factory(keyDB, &vlt.ID, "ecdh public key", "test key")
	if peerECDHkey == nil {
		t.Error("peer ecdh key is nil after being created!")
	}

	//create my ecdh key
	myECDHkey := vault.C25519Factory(keyDB, &vlt.ID, "ecdh public key", "test key")
	if myECDHkey == nil {
		t.Error("my ecdh key is nil after being created!")
	}

	// create the peer signing key
	peerSigningkey := vault.Ed25519Factory(keyDB, &vlt.ID, "peer ecdh signing key", "test key")

	// sign the peer ecdh key with the peer signing key
	peerSignature, err := peerSigningkey.Sign([]byte(*peerECDHkey.PublicKey), nil)
	if err != nil {
		t.Errorf("got error signing peer c25519 public key. Error: %s", err.Error())
		return
	}

	// create the peer diffie hellman secret
	myECDHkey.Seed = nil
	myECDHkey.PrivateKey = nil
	_, err = myECDHkey.CreateDiffieHellmanSharedSecret([]byte(*peerECDHkey.PublicKey), []byte(*peerSigningkey.PublicKey), peerSignature, "ecdh name", "ecdh description")
	if err == nil {
		t.Error("no error despite private key being nil")
		return
	}
	if err != nil {
		common.Log.Debugf("expected fail of creating ecdh with nil private key. Error: %s", err.Error())
	}
}

func TestEncryptAndDecryptSymmetricChaChaNoErrorsOptionalNonce(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key := vault.Chacha20Factory(keyDB, &vlt.ID, "test key", "just some key :D")

	plaintext := []byte(common.RandomString(128))

	nonce := make([]byte, NonceSizeSymmetric)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Errorf("error creating random nonce %s", err.Error())
		return
	}

	ciphertext, err := key.Encrypt(plaintext, nonce)
	if err != nil {
		t.Errorf("failed to encrypt plaintext with error: %s", err.Error())
		return
	}

	if hex.EncodeToString(ciphertext[vault.NonceSizeSymmetric:]) == hex.EncodeToString(plaintext) {
		t.Error("encrypted text is the same as plaintext")
		return
	}

	if len(plaintext)+vault.NonceSizeSymmetric != len(ciphertext) {
		t.Errorf("%d-byte ciphertext is not the same length as %d-byte plaintext", len(ciphertext)-vault.NonceSizeSymmetric, len(plaintext))
		return
	}

	if hex.EncodeToString(ciphertext[:vault.NonceSizeSymmetric]) != hex.EncodeToString(nonce) {
		t.Errorf("user-generated nonce not returned in ciphertext. expected %s, got %s", hex.EncodeToString(nonce), hex.EncodeToString(ciphertext[:vault.NonceSizeSymmetric]))
		return
	}

	decryptedtext, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("failed to decrypt encrypted text  with error: %s", err.Error())
		return
	}

	if hex.EncodeToString(decryptedtext) != hex.EncodeToString(plaintext) {
		t.Error("decrypted text is not the same as original plaintext!")
		return
	}
	common.Log.Debug("decrypted ciphertext is identical to original plaintext")
}

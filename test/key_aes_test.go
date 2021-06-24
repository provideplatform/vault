// +build unit

package test

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
	"github.com/provideplatform/vault/vault"
)

var aesKeyDB = dbconf.DatabaseConnection()

func TestAES256GCMEncrypt(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key encrypt decrypt unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(aesKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	encval, err := key.Encrypt(msg, nil)

	// it should not result in an error ;)
	if err != nil {
		t.Errorf("failed! symmetric encryption failed using AES-256-GCM key %s; %s", key.ID, err.Error())
		return
	}

	common.Log.Debugf("encrypted %d-byte message (%d bytes encrypted) using AES-256-GCM key for vault: %s", len(msg), len(encval), vlt.ID)
}

func TestAES256GCMEncryptNonceTooLong(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key encrypt decrypt unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(aesKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	nonce := []byte(common.RandomString(13))
	_, err = key.Encrypt(msg, nonce)

	if err != nil {
		t.Logf("got error %s", err.Error())
	}

	// it should result in an error ;)
	if err == nil {
		t.Errorf("should have failed with nonce too long error")
		return
	}

}

func TestAES256GCMEncryptShortNonce(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key encrypt decrypt unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(aesKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	nonce := []byte(common.RandomString(2))
	_, err = key.Encrypt(msg, nonce)

	if err != nil {
		t.Errorf("failed! symmetric encryption failed using AES-256-GCM key %s; %s", key.ID, err.Error())
		return
	}
}

func TestCreateKeyAES256GCM(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key create unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(aesKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
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

func TestCreateEphemeralKeyAES256GCM_privatekey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for create ephemeral AES256GCM unit test!")
		return
	}

	key, err := vault.AES256GCMEphemeralFactory(&vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create ephemeral AES-256-GCM key; Error: %s", err.Error())
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

func TestCreateAes256GCMInvalidVaultID(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ephemeral AES256GCM unit test!")
		return
	}

	_, err := vault.AES256GCMEphemeralFactory(nil, "test key", "just some key :D")
	if err == nil {
		t.Errorf("failed to invalidate key with invalid vault id: %s", vlt.ID)
		return
	}

	if err != nil {
		t.Logf("failed to invalidate key with invalid vault id: %s; Error: %v", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("invalidated invalid AES-256-GCM key for vault: %s", vlt.ID)
}

func TestEncryptAESNilPrivateKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(aesKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	plaintext := []byte(common.RandomString(128))

	key.PrivateKey = nil
	_, err = key.Encrypt(plaintext, nil)
	if err == nil {
		t.Error("failed to trap nil private key on key")
		return
	}
}

func TestEncryptAndDecryptSymmetricAESErrors(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(aesKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	plaintext := []byte(common.RandomString(128))

	ciphertext, err := key.Encrypt(plaintext, nil)
	if err != nil {
		t.Errorf("failed to encrypt plaintext with error: %s", err.Error())
		return
	}

	decryptedtext, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("failed to decrypt encrypted text  with error: %s", err.Error())
		return
	}

	if len(decryptedtext) != len(plaintext) {
		t.Errorf("%d-byte decrypted text is different length to %d-byte plaintext", len(decryptedtext), len(plaintext))
		return
	}

	if hex.EncodeToString(decryptedtext) != hex.EncodeToString(plaintext) {
		t.Error("decrypted text is not the same as original plaintext!")
		return
	}
	common.Log.Debug("decrypted ciphertext is identical to original plaintext")
}

func TestEncryptAndDecryptSymmetricAESNoErrorsOptionalNonce(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	key, err := vault.AES256GCMFactory(keyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create AES-256-GCM key for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

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

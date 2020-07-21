// +build unit

package test

import (
	"crypto/rand"
	"encoding/hex"
	"io"
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

var rsaKeyDB = dbconf.DatabaseConnection()

func TestRSA4096Verify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa4096 key verify unit test!")
		return
	}

	key := vault.RSA4096Factory(rsaKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create rsa keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))

	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using rsa keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestRSA3072Verify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa3072 key verify unit test!")
		return
	}

	key := vault.RSA3072Factory(rsaKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create rsa keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))

	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using rsa keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestRSA2048Verify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa2048 key verify unit test!")
		return
	}

	key := vault.RSA2048Factory(rsaKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create rsa keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))

	sig, err := key.Sign(msg)
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig)
	if err != nil {
		t.Errorf("failed to verify message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using rsa keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestEncryptAndDecryptRSA4096(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive asymmetric key unit test!")
		return
	}

	key := vault.RSA4096Factory(rsaKeyDB, &vlt.ID, "test key", "just some key :D")

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

func TestEncryptAndDecryptRSA3072(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive asymmetric key unit test!")
		return
	}

	key := vault.RSA3072Factory(rsaKeyDB, &vlt.ID, "test key", "just some key :D")

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

func TestEncryptAndDecryptRSA2048(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive asymmetric key unit test!")
		return
	}

	key := vault.RSA2048Factory(rsaKeyDB, &vlt.ID, "test key", "just some key :D")

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

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

	sig, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
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

	sig, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
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

	sig, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to verify message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using rsa keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestRSA2048VerifyIncorrectAlgo(t *testing.T) {
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

	sig, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS512"),
	})
	if err == nil {
		t.Errorf("failed to catch invalid algorithm specified when trying to verify message using rsa keypair for vault: %s", vlt.ID)
		return
	}

	common.Log.Debugf("correctly failed to verify message with incorrect algorithm using rsa keypair for vault: %s; err: %s", vlt.ID, err.Error())
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

func TestRSASignVerifyAlgorithms(t *testing.T) {
	tt := []struct {
		method      string
		keystrength int
	}{
		{"PS256", 2048},
		{"PS256", 3072},
		{"PS256", 4096},
		{"PS384", 2048},
		{"PS384", 3072},
		{"PS384", 4096},
		{"PS512", 2048},
		{"PS512", 3072},
		{"PS512", 4096},
		{"RS256", 2048},
		{"RS256", 3072},
		{"RS256", 4096},
		{"RS384", 2048},
		{"RS384", 3072},
		{"RS384", 4096},
		{"RS512", 2048},
		{"RS512", 3072},
		{"RS512", 4096},
	}

	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa verify unit test!")
		return
	}

	for _, tc := range tt {

		var key *vault.Key
		switch tc.keystrength {
		case 2048:
			key = vault.RSA2048Factory(rsaKeyDB, &vlt.ID, "test RSA2048 key", "unit test key")
		case 3072:
			key = vault.RSA3072Factory(rsaKeyDB, &vlt.ID, "test RSA3072 key", "unit test key")
		case 4096:
			key = vault.RSA4096Factory(rsaKeyDB, &vlt.ID, "test RSA4096 key", "unit test key")
		}

		if key == nil {
			t.Errorf("failed to create rsa%d keypair for vault: %s", tc.keystrength, vlt.ID)
			return
		}

		msg := []byte(common.RandomString(32))

		sig, err := key.Sign(msg, &vault.SigningOptions{
			Algorithm: common.StringOrNil(tc.method),
		})
		if err != nil {
			t.Errorf("failed to sign message using rsa%d keypair (%s algorithm) for vault: %s %s", tc.keystrength, tc.method, vlt.ID, err.Error())
			return
		}

		if sig == nil {
			t.Errorf("failed to sign message using rsa%d keypair (%s algorithm) for vault: %s nil signature!", tc.keystrength, tc.method, vlt.ID)
			return
		}

		err = key.Verify(msg, sig, &vault.SigningOptions{
			Algorithm: common.StringOrNil(tc.method),
		})
		if err != nil {
			t.Errorf("failed to verify message using rsa%d keypair (%s algorithm) for vault: %s %s", tc.keystrength, tc.method, vlt.ID, err.Error())
			return
		}

		common.Log.Debugf("verified message using rsa%d keypair (%s algorithm) for vault: %s", tc.keystrength, tc.method, vlt.ID)
	}
}

func TestRSASignVerifyNegativeTesting(t *testing.T) {
	tt := []struct {
		method      string
		keystrength int
	}{
		{"PS255", 2048},
		{"PS255", 3072},
		{"PS255", 4096},
	}

	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa negative unit test!")
		return
	}

	for _, tc := range tt {

		var key *vault.Key
		switch tc.keystrength {
		case 2048:
			key = vault.RSA2048Factory(rsaKeyDB, &vlt.ID, "test RSA2048 key", "unit test key")
		case 3072:
			key = vault.RSA3072Factory(rsaKeyDB, &vlt.ID, "test RSA3072 key", "unit test key")
		case 4096:
			key = vault.RSA4096Factory(rsaKeyDB, &vlt.ID, "test RSA4096 key", "unit test key")
		}

		if key == nil {
			t.Errorf("failed to create rsa%d keypair for vault: %s", tc.keystrength, vlt.ID)
			return
		}

		msg := []byte(common.RandomString(32))

		_, err := key.Sign(msg, &vault.SigningOptions{
			Algorithm: common.StringOrNil(tc.method),
		})
		if err == nil {
			t.Errorf("failed to catch invalid algorithm used to sign message using rsa%d keypair (%s algorithm) for vault: %s", tc.keystrength, tc.method, vlt.ID)
			return
		}

		common.Log.Debugf("correctly failed to sign message using rsa%d keypair using invalid algorithm (%s) for vault: %s, err: %s", tc.keystrength, tc.method, vlt.ID, err.Error())
	}
}

func TestRSA2048NilPrivateKey(t *testing.T) {
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

	key.PrivateKey = nil

	_, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err == nil {
		t.Errorf("signed message using invalid rsa keypair for vault: %s", vlt.ID)
		return
	}

	common.Log.Debugf("correctly failed to sign message using invalid rsa keypair for vault: %s; err: %s", vlt.ID, err.Error())
}

func TestRSA2048NilPublicKey(t *testing.T) {
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

	key.PublicKey = nil
	sig, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err == nil {
		t.Errorf("verified message using invalid rsa keypair for vault: %s", vlt.ID)
		return
	}

	common.Log.Debugf("correctly failed to verify message using invalid rsa keypair for vault: %s; err: %s", vlt.ID, err.Error())
}

func TestEncryptRSA2048NilPublicKey(t *testing.T) {
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

	key.PublicKey = nil
	_, err := key.Encrypt(plaintext, nonce)
	if err == nil {
		t.Errorf("encrypted plaintext without public key")
		return
	}

	common.Log.Debugf("correctly failed to encrypt with no public key err: %s", err.Error())
}

func TestEncryptAndDecryptRSA2048NilPrivateKey(t *testing.T) {
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

	key.PrivateKey = nil
	_, err = key.Decrypt(ciphertext)
	if err == nil {
		t.Errorf("decrypted ciphertext without private key")
		return
	}

	common.Log.Debugf("correctly failed to decrypt with no private key err: %s", err.Error())
}

func TestRSAEncryptTooLongPayloadNegativeTesting(t *testing.T) {
	tt := []struct {
		keyStrength  int
		payloadBytes int
	}{
		{2048, 191},
		{3072, 319},
		{4096, 447},
	}

	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa negative unit test!")
		return
	}

	for _, tc := range tt {

		var key *vault.Key
		switch tc.keyStrength {
		case 2048:
			key = vault.RSA2048Factory(rsaKeyDB, &vlt.ID, "test RSA2048 key", "unit test key")
		case 3072:
			key = vault.RSA3072Factory(rsaKeyDB, &vlt.ID, "test RSA3072 key", "unit test key")
		case 4096:
			key = vault.RSA4096Factory(rsaKeyDB, &vlt.ID, "test RSA4096 key", "unit test key")
		}

		if key == nil {
			t.Errorf("failed to create rsa%d keypair for vault: %s", tc.keyStrength, vlt.ID)
			return
		}

		plaintext := []byte(common.RandomString(tc.payloadBytes))

		nonce := make([]byte, NonceSizeSymmetric)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			t.Errorf("error creating random nonce %s", err.Error())
			return
		}

		_, err := key.Encrypt(plaintext, nonce)
		if err == nil {
			t.Errorf("encrypted too large plaintext")
			return
		}

		common.Log.Debugf("correctly failed to encrypt %d-byte message using rsa%d keypair for vault: %s, err: %s", tc.payloadBytes, tc.keyStrength, vlt.ID, err.Error())
	}
}

func TestRSAOAEPEncryptJustRightPayload(t *testing.T) {
	tt := []struct {
		keyStrength  int
		payloadBytes int
	}{
		{2048, 190},
		{3072, 318},
		{4096, 446},
	}

	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for rsa negative unit test!")
		return
	}

	for _, tc := range tt {

		var key *vault.Key
		switch tc.keyStrength {
		case 2048:
			key = vault.RSA2048Factory(rsaKeyDB, &vlt.ID, "test RSA2048 key", "unit test key")
		case 3072:
			key = vault.RSA3072Factory(rsaKeyDB, &vlt.ID, "test RSA3072 key", "unit test key")
		case 4096:
			key = vault.RSA4096Factory(rsaKeyDB, &vlt.ID, "test RSA4096 key", "unit test key")
		}

		if key == nil {
			t.Errorf("failed to create rsa%d keypair for vault: %s", tc.keyStrength, vlt.ID)
			return
		}

		plaintext := []byte(common.RandomString(tc.payloadBytes))

		nonce := make([]byte, NonceSizeSymmetric)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			t.Errorf("error creating random nonce %s", err.Error())
			return
		}

		_, err := key.Encrypt(plaintext, nonce)
		if err != nil {
			t.Errorf("error encrypting maximum-allowed plaintext (%d-bytes for RSA%d keypair. err: %s", len(plaintext), tc.keyStrength, err.Error())
		}

		common.Log.Debugf("correctly encrypted %d-byte message using rsa%d keypair for vault: %s.", len(plaintext), tc.keyStrength, vlt.ID)
	}
}

func TestRSA2048SignNilOptions(t *testing.T) {
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

	_, err := key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message with nil algorithm using rsa keypair for vault: %s", vlt.ID)
		return
	}

	common.Log.Debugf("correctly failed to sign message with nil algorithm using rsa keypair for vault: %s with err %s", vlt.ID, err.Error())
}

func TestRSA2048VerifyNilOptions(t *testing.T) {
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

	sig, err := key.Sign(msg, &vault.SigningOptions{
		Algorithm: common.StringOrNil("PS256"),
	})
	if err != nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using rsa keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("verified message with nil algorithm using rsa keypair for vault: %s", vlt.ID)
		return
	}

	common.Log.Debugf("correctly failed to verify message with nil algorithm using rsa keypair for vault: %s with err %s", vlt.ID, err.Error())
}

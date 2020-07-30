// +build unit

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

var secpKeyDB = dbconf.DatabaseConnection()

func TestCreateKeySecp256k1(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key create unit test!")
		return
	}

	key := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
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

	common.Log.Debugf("created secp256k1 keypair for vault: %s with address %s", vlt.ID, *key.Address)
}

func TestSecp256k1Sign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key signing unit test!")
		return
	}

	key := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
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

	key := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(128))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, nil)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1NoVerifyInvalidMessage(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(128))
	msg_invalid := []byte(common.RandomString(128))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg_invalid, sig, nil)
	if err == nil {
		t.Errorf("failed to not verify invalid message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify invalid message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1NoVerifyInvalidSigningKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key1 := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key1", "test signing key")
	if key1 == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	key2 := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key2", "test invalid verifying key")
	if key2 == nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(128))

	sig, err := key1.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key2.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("verified message using incorrect secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using invalid secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestCreateSECP256k1KeyWithNilDescription(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	testKey := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "secp256k1 public key", "")
	if testKey == nil {
		t.Error("failed to create secp256k1 with nil description")
	}
}

func TestSign256k1NilPrivateKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for 256k1 key signing unit test!")
		return
	}

	key := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create 256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	key.PrivateKey = nil
	_, err := key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message using 256k1 keypair with nil private key for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with 256k1 key with no private key")
	}
}

func TestSign256k1NilSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for 256k1 key signing unit test!")
		return
	}

	key := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create 256k1 keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	key.Spec = nil
	_, err := key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message using 256k1 keypair with nil spec for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with 256k1 key with nil spec")
	}
}

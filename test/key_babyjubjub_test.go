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

var babyjubjubKeyDB = dbconf.DatabaseConnection()

func TestBabyJubJubSign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key signing unit test!")
		return
	}

	key := vault.BabyJubJubFactory(babyjubjubKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create babyJubJub keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, NoAlgorithmRequired)
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

func TestBabyJubJubVerify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for babyjubjub key verify unit test!")
		return
	}

	key := vault.BabyJubJubFactory(babyjubjubKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create babyjubjub keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, NoAlgorithmRequired)
	if err != nil {
		t.Errorf("1failed to sign message using babyjubjub keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("2failed to sign message using babyjubjub keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("3failed to sign message using babyjubjub keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	err = key.Verify(msg, sig, NoAlgorithmRequired)
	if err != nil {
		t.Errorf("4failed to verify message using babyjubjub keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using babyjubjub keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSignBabyJubJubNilPrivateKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key signing unit test!")
		return
	}

	key := vault.BabyJubJubFactory(babyjubjubKeyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create BabyJubJub keypair for vault: %s", vlt.ID)
		return
	}

	msg := []byte(common.RandomString(10))
	key.PrivateKey = nil
	_, err := key.Sign(msg, NoAlgorithmRequired)
	if err == nil {
		t.Errorf("signed message using BabyJubJub keypair with nil private key for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with BabyJubJub key with no private key")
	}
}

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

func TestCreateKeyAES256GCM(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for AES-256-GCM key create unit test!")
		return
	}

	t.Error("test not implemented")
}

func TestCreateKeyChaCha20(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for ChaCha20 key create unit test!")
		return
	}

	t.Error("test not implemented")
}

func TestCreateKeyBabyJubJub(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for babyJubJub key create unit test!")
		return
	}

	t.Error("test not implemented")
}

func TestCreateKeyC25519(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for C25519 key create unit test!")
		return
	}

	key := &Key{
		VaultID:     &vault.ID,
		Name:        common.StringOrNil("C25519 key test"),
		Description: common.StringOrNil("some C25519 test key"),
		Spec:        common.StringOrNil(keySpecECCC25519),
		Usage:       common.StringOrNil(keyUsageSignVerify),
	}

	if !key.createPersisted(keyDB) {
		t.Errorf("failed to create C25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	common.Log.Debugf("created C25519 keypair for vault: %s", vault.ID)
}

func TestCreateKeyEd25519(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519 key create unit test!")
		return
	}

	t.Error("test not implemented")
}

func TestCreateKeySecp256k1(t *testing.T) {
	vault := vaultFactory()
	if vault.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key create unit test!")
		return
	}

	t.Error("test not implemented")
}

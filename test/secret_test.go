package test

import (
	"encoding/hex"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	vaultpgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

func init() {
	vaultpgputil.RequirePGP()
}

var secretDB = dbconf.DatabaseConnection()

func TestSecretStore(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description")
	if secret == nil {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}

	if hex.EncodeToString([]byte(secretText)) == hex.EncodeToString(*secret.Data) {
		t.Errorf("encrypted secret %s is the same as original secret %s", hex.EncodeToString([]byte(secretText)), hex.EncodeToString(*secret.Data))
		return
	}
}

func TestSecretStoreAndRetrieve(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description")
	if secret == nil {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}

	decryptedSecret, err := secret.Retrieve()
	if err != nil {
		t.Errorf("error retrieving secret from db %s", err.Error())
	}

	decryptedSecretAsSlice := *decryptedSecret
	if hex.EncodeToString(*decryptedSecret) != hex.EncodeToString([]byte(secretText)) {
		t.Errorf("retrieved secret not the same as stored secret! expected %s, got %s", secretText, string(decryptedSecretAsSlice[:]))
		return
	}
	t.Logf("expected decrypted secret of %s, got %s", secretText, string(decryptedSecretAsSlice[:]))
}

func TestSecretStoreNoName(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "", "type", "decription")
	if secret != nil {
		t.Errorf("validation failure in secret generation (no name provided) for vault: %s", vlt.ID)
		return
	}
	t.Log("correctly failed to validate secret without name")
}

func TestSecretStoreNoType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "", "description")
	if secret != nil {
		t.Errorf("validation failure in secret generation (no type provided) for vault: %s", vlt.ID)
		return
	}
	t.Log("correctly failed to validate secret without type")
}
func TestSecretStoreNoDescription(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "")
	if secret == nil {
		t.Errorf("failure to create secret with no description (optional) for vault: %s", vlt.ID)
		return
	}
	t.Log("correctly created secret without description")
}

func TestSecretStoreNoSecret(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := ""
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "description")
	if secret != nil {
		t.Errorf("validation failure in secret generation (no secret provided) for vault: %s", vlt.ID)
		return
	}
	t.Log("correctly failed to validate secret without secret")
}

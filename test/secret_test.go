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
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret description - possibly encrypted secret, lol")
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
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret description - possibly encrypted secret, lol")
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

// +build unit

package test

import (
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

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
}

func TestSecretStoreAndResponse(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	t.Logf("generated secret %s", secretText)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description 123456")
	if secret == nil {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}

	//next we will list the secrets for the vault, select our secret and retrieve the text
	storedSecret := &vault.Secret{}
	vlt.ListSecretsQuery(secretDB).Where("secrets.id=?", secret.ID).Find(&storedSecret)
	secretResp, err := storedSecret.AsResponse()
	if err != nil {
		t.Errorf("error retrieving secret %s", err.Error())
	}

	if *secretResp.Value != secretText {
		t.Errorf("got incorrect secret back, expected %s, got %s", secretText, *storedSecret.Value)
		return
	}
	t.Logf("got expected secret back")
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

func TestSecretStoreTooLong(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(4097)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "description")
	if secret != nil {
		t.Errorf("validation failure in secret generation (no secret provided) for vault: %s", vlt.ID)
		return
	}
	t.Log("correctly failed to validate secret that was too long")
}

func TestSecretDelete(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secretName := "to be deleted secret"
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), secretName, "secret type", "secret to be deleted")
	if secret == nil {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}

	if !secret.Delete(secretDB) {
		t.Errorf("error deleting secret")
		return
	}

	//next we will list the secrets for the vault, select our secret and retrieve the text
	deletedSecret := &vault.Secret{}
	vlt.ListSecretsQuery(secretDB).Where("secrets.id=?", secret.ID).Find(&deletedSecret)

	_, err := deletedSecret.AsResponse()
	if err == nil {
		t.Errorf("no error retrieving deleted secret")
		return
	}

	t.Logf("secret deleted as expected %s", err.Error())
}

func TestSecretDeleteNilSecretID(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secretName := "to be fail deleted secret"
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), secretName, "secret type", "secret to be fail deleted")
	if secret == nil {
		t.Errorf("failed to create fail secret for vault: %s", vlt.ID)
		return
	}

	secret.ID = uuid.Nil
	if secret.Delete(secretDB) {
		t.Errorf("got no error deleting invalid secret")
		return
	}
}

func TestGetVaultSecret(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	t.Logf("generated secret %s", secretText)
	secret := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description 123456")
	if secret == nil {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}

	storedSecret := vault.GetVaultSecret(secret.ID.String(), vlt.ID.String(), vlt.ApplicationID, vlt.OrganizationID, vlt.UserID)
	if storedSecret == nil {
		t.Errorf("error retrieving secret - secret not found")
	}

	decryptedSecret, err := storedSecret.AsResponse()
	if err != nil {
		t.Errorf("error retrieving secret %s", err.Error())
		return
	}

	if *decryptedSecret.Value != secretText {
		t.Errorf("got incorrect secret back, expected %s, got %s", secretText, *storedSecret.Value)
		return
	}

	t.Logf("got expected secret back")
}

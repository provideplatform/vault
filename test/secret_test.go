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
	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description")
	if err != nil {
		t.Errorf("failed to create secret for vault: %s; Error: %s", vlt.ID, err.Error())
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
	secret, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description 123456")
	if err != nil {
		t.Errorf("failed to create secret for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	//next we will list the secrets for the vault, select our secret and retrieve the text
	storedSecret := &vault.Secret{}
	//FIXME is this in a method somewhere - this is too much code
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
	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "", "type", "decription")
	if err == nil {
		t.Errorf("created secret with no name for vault: %s", vlt.ID)
		return
	}
}

func TestSecretStoreNoType(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "", "description")
	if err == nil {
		t.Errorf("created secret with no type for vault: %s", vlt.ID)
		return
	}
}
func TestSecretStoreNoDescription(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "")
	if err != nil {
		t.Errorf("failed to create secret with no (optional) description for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}
}

func TestSecretStoreNoSecret(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := ""
	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "description")
	if err == nil {
		t.Errorf("created secret with no secret for vault: %s", vlt.ID)
		return
	}
}

func TestSecretStoreTooLong(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(4097)
	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "description")
	if err == nil {
		t.Errorf("created secret too long for vault: %s", vlt.ID)
		return
	}
}

func TestSecretDelete(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secret store unit test!")
		return
	}

	secretText := common.RandomString(32)
	secretName := "to be deleted secret"
	secret, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), secretName, "secret type", "secret to be deleted")
	if err != nil {
		t.Errorf("failed to create secret for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	if !secret.Delete(secretDB) {
		t.Errorf("error deleting secret")
		return
	}

	//next we will list the secrets for the vault, select our secret and retrieve the text
	deletedSecret := &vault.Secret{}
	//FIXME this should be a method call
	vlt.ListSecretsQuery(secretDB).Where("secrets.id=?", secret.ID).Find(&deletedSecret)

	_, err = deletedSecret.AsResponse()
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
	secret, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), secretName, "secret type", "secret to be fail deleted")
	if err != nil {
		t.Errorf("failed to create secret for vault: %s; Error: %s", vlt.ID, err.Error())
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
	secret, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "secret name", "secret type", "secret description 123456")
	if err != nil {
		t.Errorf("failed to create secret for vault: %s; Error: %s", vlt.ID, err.Error())
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
}

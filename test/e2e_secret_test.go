// +build integration

package test

import (
	"fmt"
	"testing"

	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go/api/vault"
)

func TestAPIListSecrets(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := fmt.Sprintf("secret-%s", common.RandomString(128))
	name := fmt.Sprintf("secretname-%s", common.RandomString(12))
	description := "secret description"
	secretType := "secret type"

	status, secretresponse, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
	//assert type to get something sensible from empty interface
	response, _ := secretresponse.(map[string]interface{})
	t.Logf("response from handler: %s", response)

	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault")
		return
	}

	name2 := fmt.Sprintf("secretname2-%s", common.RandomString(12))
	status, _, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name2, description, secretType)
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	status, listVaultSecretsResponse, err := provide.ListVaultSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}

	listOfSecrets := listVaultSecretsResponse.([]interface{})
	firstSecret := listOfSecrets[0].(map[string]interface{})
	secondSecret := listOfSecrets[1].(map[string]interface{})

	if firstSecret["name"] != name {
		t.Errorf("Error retrieving first secret, expected %s, got %s", name, firstSecret["name"])
		return
	}

	if secondSecret["name"] != name2 {
		t.Errorf("Error retrieving second secret, expected %s, got %s", name, secondSecret["name"])
		return
	}
}

func TestAPICreateSecret(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := common.RandomString(128)
	name := "secret name"
	description := "secret description"
	secretType := "secret type"
	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}
}

func TestAPICreateSecretTooLong(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := common.RandomString(9000)
	name := "secret name"
	description := "secret description"
	secretType := "secret type"
	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

	if status == 201 {
		t.Errorf("created secret that was %d-bytes-long!", len(secret))
		return
	}
}

func TestAPICreateSecretNoName(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := common.RandomString(9000)
	name := ""
	description := "secret description"
	secretType := "secret type"
	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

	if status == 201 {
		t.Errorf("created secret with no name!")
		return
	}
}

func TestAPICreateSecretNoType(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := common.RandomString(9000)
	name := "secret name"
	description := "secret description"
	secretType := ""
	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

	if status == 201 {
		t.Error("created secret with no type!")
		return
	}
}

func TestAPICreateSecretNoData(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := ""
	name := "secret name"
	description := "secret description"
	secretType := "secret type"
	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

	if status == 201 {
		t.Error("created secret with no data!")
		return
	}
}

func TestAPICreateAndRetrieveSecret(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	secret := common.RandomString(128)
	name := "secret name"
	description := "secret description"
	secretType := "secret type"

	status, createSecretResponse, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	response, _ := createSecretResponse.(map[string]interface{})

	status, retrieveSecretResponse, err := provide.RetrieveVaultSecret(*token, vault.ID.String(), response["id"].(string), map[string]interface{}{})

	retrievedSecret, _ := retrieveSecretResponse.(map[string]interface{})

	if retrievedSecret["value"].(string) != secret {
		t.Errorf("secret returned mismatch.  Expected %s, got %s", secret, retrievedSecret["secret"].(string))
		return
	}
}

func TestAPIDeleteSecret(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	status, secretResponse, err := provide.CreateVaultSecret(*token, vault.ID.String(), "secret to delete", "deleted secret", "secret to be deleted", "test_secret")
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	response, _ := secretResponse.(map[string]interface{})

	status, _, err = provide.DeleteVaultSecret(*token, vault.ID.String(), response["id"].(string))
	if err != nil || status != 204 {
		t.Errorf("failed to delete secret for vault: %s", err.Error())
		return
	}

	status, listVaultSecretsResponse, err := provide.ListVaultSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}

	listOfSecrets := listVaultSecretsResponse.([]interface{})

	if len(listOfSecrets) != 0 {
		t.Errorf("expceted no secrets stored in vault, instead returned %d", len(listOfSecrets))
		return
	}
}

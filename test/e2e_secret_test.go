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
	var secretError error
	_, secretError = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

	if secretError != nil {
		t.Errorf("failed to create secret for vault")
		return
	}

	name2 := fmt.Sprintf("secretname2-%s", common.RandomString(12))
	_, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name2, description, secretType)
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	listVaultSecretsResponse, err := provide.ListVaultSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}
	t.Logf("list secrets returned %+v", listVaultSecretsResponse)
	firstSecret := listVaultSecretsResponse[0]
	secondSecret := listVaultSecretsResponse[1]

	if *firstSecret.Name != name {
		t.Errorf("Error retrieving first secret, expected %s, got %s", name, *firstSecret.Name)
		return
	}

	if *secondSecret.Name != name2 {
		t.Errorf("Error retrieving second secret, expected %s, got %s", name, *secondSecret.Name)
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
	_, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
	if err != nil {
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
	_, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
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
	_, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

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
	_, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

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
	_, err = provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)

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

	createSecretResponse, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	retrieveSecretResponse, err := provide.RetrieveVaultSecret(*token, vault.ID.String(), createSecretResponse.ID.String(), map[string]interface{}{})

	if *retrieveSecretResponse.Value != secret {
		t.Errorf("secret returned mismatch.  Expected %s, got %s", secret, *retrieveSecretResponse.Value)
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

	secretResponse, err := provide.CreateVaultSecret(*token, vault.ID.String(), "secret to delete", "deleted secret", "secret to be deleted", "test_secret")
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	err = provide.DeleteVaultSecret(*token, vault.ID.String(), secretResponse.ID.String())
	if err != nil {
		t.Errorf("failed to delete secret for vault: %s", err.Error())
		return
	}

	listVaultSecretsResponse, err := provide.ListVaultSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}

	if len(listVaultSecretsResponse) != 0 {
		t.Errorf("expceted no secrets stored in vault, instead returned %d", len(listVaultSecretsResponse))
		return
	}
}

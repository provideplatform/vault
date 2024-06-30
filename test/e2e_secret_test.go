//go:build integration || secret
// +build integration secret

/*
 * Copyright 2017-2024 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test

import (
	"fmt"
	"testing"

	provide "github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/vault/common"
)

func TestAPILIstSecretTypeFilter(t *testing.T) {

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
	secretType := "filtered"
	var secretError error
	_, secretError = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})

	if secretError != nil {
		t.Errorf("failed to create secret for vault")
		return
	}

	name2 := fmt.Sprintf("secretname2-%s", common.RandomString(12))
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name2,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	name3 := fmt.Sprintf("secretname3-%s", common.RandomString(12))
	secret3Type := "should_not_appear"
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name3,
		"description": description,
		"value":       secret,
		"type":        secret3Type,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	listVaultSecretsResponse, err := provide.ListSecrets(*token, vault.ID.String(), map[string]interface{}{"type": secretType})
	if err != nil {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}

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

	if len(listVaultSecretsResponse) > 2 {
		t.Errorf("secrets not filtered - expected 2 secrets, got %d", len(listVaultSecretsResponse))
		return
	}

	if *firstSecret.Type != secretType || *secondSecret.Type != secretType {
		t.Error("unfiltered response returned")
		return
	}
}

func TestAPILIstSecretTypeFilter_NegativeTest(t *testing.T) {

	// add the secrets out of order, and expect to get thte same out of order secrets returned, unfiltered
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
	secretType := "filtered"
	var secretError error
	_, secretError = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})

	if secretError != nil {
		t.Errorf("failed to create secret for vault")
		return
	}

	name3 := fmt.Sprintf("secretname3-%s", common.RandomString(12))
	secret3Type := "should_not_appear"
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name3,
		"description": description,
		"value":       secret,
		"type":        secret3Type,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	name2 := fmt.Sprintf("secretname2-%s", common.RandomString(12))
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name2,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	listVaultSecretsResponse, err := provide.ListSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}

	firstSecret := listVaultSecretsResponse[0]
	secondSecret := listVaultSecretsResponse[1]
	thirdSecret := listVaultSecretsResponse[2]

	if *firstSecret.Name != name {
		t.Errorf("Error retrieving first secret, expected %s, got %s", name, *firstSecret.Name)
		return
	}

	if *secondSecret.Name != name3 {
		t.Errorf("Error retrieving second secret added, expected %s, got %s", name, *secondSecret.Name)
		return
	}

	if *thirdSecret.Name != name2 {
		t.Errorf("Error retrieving third secret added, expected %s, got %s", name, *secondSecret.Name)
		return
	}

	if len(listVaultSecretsResponse) != 3 {
		t.Errorf("unfiltered secrets - expected 3 secrets, got %d", len(listVaultSecretsResponse))
		return
	}
}

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
	_, secretError = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})

	if secretError != nil {
		t.Errorf("failed to create secret for vault")
		return
	}

	name2 := fmt.Sprintf("secretname2-%s", common.RandomString(12))
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name2,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	listVaultSecretsResponse, err := provide.ListSecrets(*token, vault.ID.String(), map[string]interface{}{})
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
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}
}

// TestAPICreateSecretTooLong commented out because max secret length is currently 1GB
// func TestAPICreateSecretTooLong(t *testing.T) {

// 	token, err := userTokenFactory()
// 	if err != nil {
// 		t.Errorf("failed to create token; %s", err.Error())
// 		return
// 	}

// 	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
// 	if err != nil {
// 		t.Errorf("failed to create vault; %s", err.Error())
// 		return
// 	}

// 	maxSecretLength := 4096 * 32
// 	secret := common.RandomString(maxSecretLength + 1)
// 	name := "secret name"
// 	description := "secret description"
// 	secretType := "secret type"
// 	_, err = provide.CreateSecret(*token, vault.ID.String(), secret, name, description, secretType)
// 	if err == nil {
// 		t.Errorf("allowed creation of secret that exceeds max length")
// 		return
// 	}
// }

func TestAPICreateSecretMaxSize(t *testing.T) {

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

	maxSecretLength := 4096 * 32
	secret := common.RandomString(maxSecretLength)
	name := "secret name"
	description := "secret description"
	secretType := "secret type"
	createSecretResponse, err := provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})
	if err != nil {
		t.Errorf("failed creating max length secret. Error: %s", err.Error())
		return
	}

	// now ensure we get the same max length secret back
	retrieveSecretResponse, err := provide.FetchSecret(*token, vault.ID.String(), createSecretResponse.ID.String(), map[string]interface{}{})

	if *retrieveSecretResponse.Value != secret {
		t.Errorf("secret returned mismatch.  Expected %s, got %s", secret, *retrieveSecretResponse.Value)
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
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})

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
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})

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
	_, err = provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})

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

	createSecretResponse, err := provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        name,
		"description": description,
		"value":       secret,
		"type":        secretType,
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	retrieveSecretResponse, err := provide.FetchSecret(*token, vault.ID.String(), createSecretResponse.ID.String(), map[string]interface{}{})

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

	secretResponse, err := provide.CreateSecret(*token, vault.ID.String(), map[string]interface{}{
		"name":        "secret to delete",
		"description": "deleted secret",
		"value":       "secret to be deleted",
		"type":        "test_secret",
	})
	if err != nil {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	err = provide.DeleteSecret(*token, vault.ID.String(), secretResponse.ID.String())
	if err != nil {
		t.Errorf("failed to delete secret for vault: %s", err.Error())
		return
	}

	listVaultSecretsResponse, err := provide.ListSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}

	if len(listVaultSecretsResponse) != 0 {
		t.Errorf("expceted no secrets stored in vault, instead returned %d", len(listVaultSecretsResponse))
		return
	}
}

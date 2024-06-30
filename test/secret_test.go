//go:build unit
// +build unit

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
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
	"github.com/provideplatform/vault/vault"
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

	t.Logf("secret returned %+v", *secret)
	storedSecret := vault.GetVaultSecret(secret.ID.String(), vlt.ID.String(), vlt.ApplicationID, vlt.OrganizationID, vlt.UserID)

	decryptedSecret, _ := storedSecret.AsResponse()

	if *decryptedSecret.Value != secretText {
		t.Errorf("got incorrect secret back, expected %s, got %s", secretText, *decryptedSecret.Value)
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

// func TestSecretStoreTooLong(t *testing.T) {
// 	vlt := vaultFactory()
// 	if vlt.ID == uuid.Nil {
// 		t.Error("failed! no vault created for secret store unit test!")
// 		return
// 	}

// 	secretText := common.RandomString(vault.MaxSecretLengthInBytes + 1)
// 	_, err := vault.SecretFactory(secretDB, &vlt.ID, []byte(secretText), "name", "secret type", "description")
// 	if err == nil {
// 		t.Errorf("created secret too long for vault: %s", vlt.ID)
// 		return
// 	}
// }

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

	t.Logf("secret returned %+v", *secret)
	deletedSecret := vault.GetVaultSecret(secret.ID.String(), vlt.ID.String(), vlt.ApplicationID, vlt.OrganizationID, vlt.UserID)

	if deletedSecret.ID != uuid.Nil {
		t.Errorf("retrieved deleted secret")
		return
	}
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

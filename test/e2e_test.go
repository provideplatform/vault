// +build integration

package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
	cryptovault "github.com/provideapp/vault/vault"
	provide "github.com/provideservices/provide-go"
)

func keyFactory(token, vaultID, keyType, keyUsage, keySpec, keyName, keyDescription string) (*vault.Key, error) {

	status, resp, err := provide.CreateVaultKey(token, vaultID, map[string]interface{}{
		"type":        keyType,
		"usage":       keyUsage,
		"spec":        keySpec,
		"name":        keyName,
		"description": keyDescription,
	})

	if err != nil || status != 201 {
		return nil, fmt.Errorf("failed to create key error: %s", err.Error())
	}

	key := &vault.Key{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall key data: %s", err.Error())
	}
	json.Unmarshal(respRaw, &key)
	return key, nil
}

func vaultFactory(token, name, desc string) (*vault.Vault, error) {
	status, resp, err := provide.CreateVault(token, map[string]interface{}{
		"name":        name,
		"description": desc,
	})
	if err != nil || status != 201 {
		return nil, err
	}
	vlt := &vault.Vault{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(respRaw, &vlt)
	return vlt, nil
}

func userFactory(email, password string) (*uuid.UUID, error) {
	status, resp, err := provide.CreateUser("", map[string]interface{}{
		"first_name": "A",
		"last_name":  "User",
		"email":      email,
		"password":   password,
	})
	if err != nil || status != 201 {
		return nil, errors.New("failed to create user")
	}
	var usrID *uuid.UUID
	if usr, usrOk := resp.(map[string]interface{}); usrOk {
		if id, idok := usr["id"].(string); idok {
			usrUUID, err := uuid.FromString(id)
			if err != nil {
				return nil, err
			}
			usrID = &usrUUID
		}
	}
	return usrID, nil
}

func userTokenFactory() (*string, error) {
	newUUID, err := uuid.NewV4()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error generating uuid %s", err.Error()))
	}
	email := fmt.Sprintf("%s@provide-integration-tests.com", newUUID.String())
	password := fmt.Sprintf("%s", newUUID.String())

	userID, err := userFactory(email, password)
	if err != nil || userID == nil {
		return nil, err
	}

	status, resp, err := provide.Authenticate(email, password)
	if err != nil || status != 201 {
		return nil, errors.New("failed to authenticate user")
	}
	var token *string
	if authresp, authrespOk := resp.(map[string]interface{}); authrespOk {
		if tok, tokOk := authresp["token"].(map[string]interface{}); tokOk {
			if tokenstr, tokenstrOk := tok["token"].(string); tokenstrOk {
				token = common.StringOrNil(tokenstr)
			}
		}
	}
	return token, nil
}

func TestAPICreateVault(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

}

func TestAPICreateKey(t *testing.T) {
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

	status, _, err := provide.CreateVaultKey(*token, vault.ID.String(), map[string]interface{}{
		"type":        "asymmetric",
		"usage":       "sign/verify",
		"spec":        "secp256k1",
		"name":        "integration test ethereum key",
		"description": "organization eth/stablecoin wallet",
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create key error: %s", err.Error())
		return
	}
}

func TestAPIDeleteKey(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "secp256k1", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	status, _, err := provide.DeleteVaultKey(*token, vault.ID.String(), key.ID.String())
	if err != nil || status != 204 {
		t.Errorf("failed to delete key for vault: %s", err.Error())
		return
	}
}

func TestAPISign(t *testing.T) {

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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "secp256k1", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	status, _, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), "hello world")
	if err != nil || status != 201 {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
}

func TestAPIVerifySecp256k1Signature(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecECCSecp256k1, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	messageToSign := common.RandomString(1000)
	status, sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign)
	if err != nil || status != 201 {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
	//assert type to get something sensible from empty interface
	response, _ := sigresponse.(map[string]interface{})

	status, _, err = provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, response["signature"].(string))
	if err != nil || status != 201 {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}
}

func TestAPIVerifyEd25519Signature(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecECCEd25519, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	messageToSign := common.RandomString(1000)
	status, sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign)
	if err != nil || status != 201 {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
	//assert type to get something sensible from empty interface
	response, _ := sigresponse.(map[string]interface{})

	status, _, err = provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, response["signature"].(string))
	if err != nil || status != 201 {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}
}

func TestAPIEncrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)
	nonce := "1"

	status, _, err := provide.EncryptWithNonce(*token, vault.ID.String(), key.ID.String(), data, nonce)

	if err != nil || status != 200 {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}
}

func TestAPIChachaDecrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "ChaCha20", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)
	nonce := "1"

	status, encryptedDataResponse, err := provide.EncryptWithNonce(*token, vault.ID.String(), key.ID.String(), data, nonce)

	encryptedData, _ := encryptedDataResponse.(map[string]interface{})

	if err != nil || status != 200 {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	status, decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedData["data"].(string),
	})
	decryptedData, _ := decryptedDataResponse.(map[string]interface{})

	if decryptedData["data"].(string) != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedData["data"].(string))
		return
	}
}

func TestAPIDecrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)
	nonce := common.RandomString(12)

	status, encryptedDataResponse, err := provide.EncryptWithNonce(*token, vault.ID.String(), key.ID.String(), data, nonce)

	encryptedData, _ := encryptedDataResponse.(map[string]interface{})

	if err != nil || status != 200 {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	status, decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedData["data"].(string),
	})

	decryptedData, _ := decryptedDataResponse.(map[string]interface{})

	if decryptedData["data"].(string) != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedData["data"].(string))
		return
	}
}

func TestAPIDecryptNoNonce(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)

	status, encryptedDataResponse, err := provide.EncryptWithoutNonce(*token, vault.ID.String(), key.ID.String(), data)

	encryptedData, _ := encryptedDataResponse.(map[string]interface{})

	if err != nil || status != 200 {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	status, decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedData["data"].(string),
	})
	decryptedData, _ := decryptedDataResponse.(map[string]interface{})

	if decryptedData["data"].(string) != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedData["data"].(string))
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

	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), secret, name, description, secretType)
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
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

	if retrievedSecret["rawsecret"].(string) != secret {
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

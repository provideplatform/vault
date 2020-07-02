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
	common.Log.Debugf("%s", resp)
	return usrID, nil
}

func userTokenFactory() (*string, error) {
	newUUID, err := uuid.NewV4()
	if err != nil {
		common.Log.Debugf("error generating uuid %s", err.Error())
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
	common.Log.Debugf("token returned: %s", *token)
	return token, nil
}

// func organizationFactory(token, name string) (*uuid.UUID, error) {
// 	status, resp, err := provide.CreateOrganization(token, map[string]interface{}{
// 		"name": name,
// 	})
// 	if err != nil || status != 200 {
// 		return nil, errors.New("failed to create organization")
// 	}
// 	var orgID *uuid.UUID
// 	if org, orgOk := resp.(map[string]interface{}); orgOk {
// 		if id, idok := org["id"].(string); idok {
// 			orgUUID, err := uuid.FromString(id)
// 			if err != nil {
// 				return nil, err
// 			}
// 			orgID = &orgUUID
// 		}
// 	}
// 	return orgID, nil
// }

// e2e suite

func TestAPICreateVault(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}
	t.Log("here1")
	vault, err := vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}
	t.Logf("vault %T", vault)
	common.Log.Debugf("created vault; %s", vault.ID.String())
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

func TestAPIVerifySignature(t *testing.T) {
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

	status, sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), "hello world")
	if err != nil || status != 201 {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
	//assert type to get something sensible from empty interface
	response, _ := sigresponse.(map[string]interface{})

	status, _, err = provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), "hello world", response["signature"].(string))
	if err != nil || status != 201 {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}
}

func TestAPIEncrypt(t *testing.T) {
	// status, _, err := provide.Encrypt(nil, map[string]interface{}{})
	// if err != nil || status != 200 {
	// 	t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
	// 	return
	// }
}

func TestAPIDecrypt(t *testing.T) {
	// status, _, err := provide.Decrypt(nil, map[string]interface{}{})
	// if err != nil || status != 200 {
	// 	t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
	// 	return
	// }
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

	status, _, err := provide.ListVaultSecrets(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
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

	status, _, err := provide.CreateVaultSecret(*token, vault.ID.String(), map[string]interface{}{
		"secret": "1234", "name": "secretsecret", "type": "secret type",
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}

	//TODO pull the secret back and make sure it's what we put in
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

	status, secretResponse, err := provide.CreateVaultSecret(*token, vault.ID.String(), map[string]interface{}{
		"secret": "1234", "name": "secretsecret", "type": "secret type",
	})
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
}

// +build integration

package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
	provide "github.com/provideservices/provide-go"
)

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
	email := "a.user@prvd.local"
	password := "a.user5555"

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

	vault, err := vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	common.Log.Debugf("created vault; %s", vault.ID)
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

	status, _, err := provide.CreateVaultKey(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil || status != 201 {
		t.Errorf("failed to create key for org id: %s", err.Error()) //vlt.ID?? not sure where the vault is being defined here
		return
	}
}

func TestAPIDeleteKey(t *testing.T) {
	status, _, err := provide.DeleteVaultKey("a", "b", "c")
	if err != nil || status != 204 {
		t.Errorf("failed to delete key for vault: %s", err.Error())
		return
	}
}

func TestAPISign(t *testing.T) {
	status, _, err := provide.SignMessage("a", "b", "c", "d")
	if err != nil || status != 201 {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
}

func TestAPIVerifySignature(t *testing.T) {
	status, _, err := provide.VerifySignature("a", "b", "c", "d", "e")
	if err != nil || status != 200 {
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
	status, _, err := provide.ListVaultSecrets("a", "b", map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", err.Error())
		return
	}
}

func TestAPICreateSecret(t *testing.T) {
	status, _, err := provide.CreateVaultSecret("a", "b", map[string]interface{}{
		"organization_id": "asdf",
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", err.Error())
		return
	}
}

func TestAPIDeleteSecret(t *testing.T) {
	status, _, err := provide.DeleteVaultSecret("a", "b", "c")
	if err != nil || status != 204 {
		t.Errorf("failed to delete secret for vault: %s", err.Error())
		return
	}
}

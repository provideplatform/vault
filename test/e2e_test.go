// +build integration

package test

import (
	"errors"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go"
)

func init() {
	userFactory()
}

func userFactory() (*uuid.UUID, error) {
	status, resp, err := provide.CreateUser("", map[string]interface{}{
		"first_name": "A",
		"last_name":  "User",
		"email":      "a.user@prvd.local",
		"password":   "a.user5555",
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
	status, _, err := userFactory()
	if err != nil || status != 201 {
		return err
	}

	status, resp, err := provide.Authenticate(email, passwd)
	if err != nil || status != 201 {
		return errors.New("failed to authenticate user")
	}
	var token *string
	if authresp, authrespOk := resp.(map[string]interface{}); authrespOk {
		if tok, tokOk := authresp["token"].(map[string]interface{}); tokOk {
			if tokenstr, tokenstrOk := tok["token"].(string); tokenstrOk {
				token = common.StringOrNil(tokenstr)
			}
		}
	}
	common.Log.Debugf("%s", resp)
	return token, nil
}

func organizationFactory(token, name string) (*uuid.UUID, error) {
	status, resp, err := provide.CreateOrganization(token, map[string]interface{}{
		"name": name,
	})
	if err != nil || status != 200 {
		return nil, errors.New("failed to create organization")
	}
	var orgID *uuid.UUID
	if org, orgOk := resp.(map[string]interface{}); orgOk {
		if id, idok := org["id"].(string); idok {
			orgUUID, err := uuid.FromString(id)
			if err != nil {
				return nil, err
			}
			orgID = &orgUUID
		}
	}
	return orgID, nil
}

// e2e suite

func TestAPICreateVault(t *testing.T) {
	status, _, err := provide.CreateVault(nil, map[string]interface{}{
		"organization_id": "asdf",
	})
	if err != nil || status != 200 {
		t.Errorf("failed to create vault for org id: %s", "asdf")
		return
	}
}

func TestAPICreateKey(t *testing.T) {
	status, _, err := provide.CreateVaultKey(nil, map[string]interface{}{
		"organization_id": "asdf",
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create key for vault: %s", vlt.ID)
		return
	}
}

func TestAPIDeleteKey(t *testing.T) {
	status, _, err := provide.DeleteVaultKey(nil, map[string]interface{}{})
	if err != nil || status != 204 {
		t.Errorf("failed to delete key for vault: %s", vlt.ID)
		return
	}
}

func TestAPISign(t *testing.T) {
	status, _, err := provide.SignMessage(nil, map[string]interface{}{
		"organization_id": "asdf",
	})
	if err != nil || status != 201 {
		t.Errorf("failed to sign message for vault: %s", vlt.ID)
		return
	}
}

func TestAPIVerifySignature(t *testing.T) {
	status, _, err := provide.VerifySignature(nil, map[string]interface{}{
		"message":   "FIXME",
		"signature": "FIXME",
	})
	if err != nil || status != 200 {
		t.Errorf("failed to verify signature for vault: %s", vlt.ID)
		return
	}
}

func TestAPIEncrypt(t *testing.T) {
	status, _, err := provide.Encrypt(nil, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
		return
	}
}

func TestAPIDecrypt(t *testing.T) {
	status, _, err := provide.Decrypt(nil, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
		return
	}
}

func TestAPIListSecrets(t *testing.T) {
	status, _, err := provide.ListVaultSecrets(nil, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", vlt.ID)
		return
	}
}

func TestAPICreateSecret(t *testing.T) {
	status, _, err := provide.CreateVaultSecret(nil, map[string]interface{}{
		"organization_id": "asdf",
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}
}

func TestAPIDeleteSecret(t *testing.T) {
	status, _, err := provide.DeleteVaultSecret(nil, map[string]interface{}{})
	if err != nil || status != 204 {
		t.Errorf("failed to delete secret for vault: %s", vlt.ID)
		return
	}
}

// +build integration

package test

import (
	"testing"

	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

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

func TestAPICreateVault(t *testing.T) {
	status, _, err := provide.CreateVault(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 200 {
		t.Errorf("failed to create vault for org id: %s", organizationID)
		return
	}
}

func TestAPICreateKey(t *testing.T) {
	status, _, err := provide.CreateVaultKey(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create key for vault: %s", vlt.ID)
		return
	}
}

func TestAPIDeleteKey(t *testing.T) {
	status, _, err := provide.DeleteVaultKey(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 204 {
		t.Errorf("failed to delete key for vault: %s", vlt.ID)
		return
	}
}

func TestAPISign(t *testing.T) {
	status, _, err := provide.SignMessage(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 201 {
		t.Errorf("failed to sign message for vault: %s", vlt.ID)
		return
	}
}

func TestAPIVerifySignature(t *testing.T) {
	status, _, err := provide.VerifySignature(*orgToken.Token, map[string]interface{}{
		"message":   "FIXME",
		"signature": "FIXME",
	})
	if err != nil || status != 200 {
		t.Errorf("failed to verify signature for vault: %s", vlt.ID)
		return
	}
}

func TestAPIEncrypt(t *testing.T) {
	status, _, err := provide.Encrypt(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
		return
	}
}

func TestAPIDecrypt(t *testing.T) {
	status, _, err := provide.Decrypt(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
		return
	}
}

func TestAPIListSecrets(t *testing.T) {
	status, _, err := provide.ListVaultSecrets(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", vlt.ID)
		return
	}
}

func TestAPICreateSecret(t *testing.T) {
	status, _, err := provide.CreateVaultSecret(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create secret for vault: %s", vlt.ID)
		return
	}
}

func TestAPIDeleteSecret(t *testing.T) {
	status, _, err := provide.DeleteVaultSecret(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 204 {
		t.Errorf("failed to delete secret for vault: %s", vlt.ID)
		return
	}
}

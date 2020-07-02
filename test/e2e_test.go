// +build integration

package test

import (
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go"
)

var organizationID *uuid.UUID

func init() {

}

func TestCreateVault(t *testing.T) {
	status, _, err := provide.CreateVault(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 200 {
		t.Errorf("failed to create vault for org id: %s", organizationID)
		return
	}
}

func TestCreateKey(t *testing.T) {
	status, _, err := provide.CreateVaultKey(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 201 {
		t.Errorf("failed to create key for vault: %s", vlt.ID)
		return
	}
}

func TestSign(t *testing.T) {
	status, _, err := provide.SignMessage(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err != nil || status != 201 {
		t.Errorf("failed to sign message for vault: %s", vlt.ID)
		return
	}
}

func TestVerifySignature(t *testing.T) {
	status, _, err := provide.VerifySignature(*orgToken.Token, map[string]interface{}{
		"message":   "FIXME",
		"signature": "FIXME",
	})
	if err != nil || status != 200 {
		t.Errorf("failed to verify signature for vault: %s", vlt.ID)
		return
	}
}

func TestEncrypt(t *testing.T) {
	status, _, err := provide.Encrypt(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
		return
	}
}

func TestDecrypt(t *testing.T) {
	status, _, err := provide.Decrypt(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to decrypt message for vault: %s", vlt.ID)
		return
	}
}

func TestListSecrets(t *testing.T) {
	status, _, err := provide.ListVaultSecrets(*orgToken.Token, map[string]interface{}{})
	if err != nil || status != 200 {
		t.Errorf("failed to list secrets for vault: %s", vlt.ID)
		return
	}
}

func TestCreateSecret(t *testing.T) {
	status, _, err := provide.CreateVaultSecret(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err == nil && status == 201 {
		common.Log.Debugf("Created default vault for organization: %s", *organization.Name)
		msg.Ack()
	} else {
		common.Log.Warningf("Failed to create default vault for organization: %s", *organization.Name)
		natsutil.AttemptNack(msg, createOrganizationTimeout)
	}
}

func TestDeleteSecret(t *testing.T) {
	status, _, err := provide.DeleteVaultSecret(*orgToken.Token, map[string]interface{}{
		"organization_id": organizationID,
	})
	if err == nil && status == 201 {
		common.Log.Debugf("Created default vault for organization: %s", *organization.Name)
		msg.Ack()
	} else {
		common.Log.Warningf("Failed to create default vault for organization: %s", *organization.Name)
		natsutil.AttemptNack(msg, createOrganizationTimeout)
	}
}

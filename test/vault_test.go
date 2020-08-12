// +build unit

package test

import (
	"fmt"
	"testing"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	vaultpgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

func init() {
	vaultpgputil.RequirePGP()
}

var vaultDB = dbconf.DatabaseConnection()

func vaultFactory() *vault.Vault {
	associationID, _ := uuid.NewV4()

	return vault.New(
		vaultDB,
		fmt.Sprintf("vault@%d", time.Now().Unix()),
		"a vault under test...",
		nil,
		&associationID,
		nil,
	)
}

func TestCreateVaultFailsWithoutValidAssociation(t *testing.T) {
	vlt := &vault.Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("invalid vault"),
		Description:    common.StringOrNil("a test vault with invalid app, org or user association"),
	}

	success := vlt.Create(vaultDB)
	if success || vlt.ID != uuid.Nil {
		t.Error("failed! invalid vault was created anyway!")
	}
}

func TestValidateVaultFailsWithoutMasterKey(t *testing.T) {
	vlt := &vault.Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("invalid vault"),
		Description:    common.StringOrNil("a test vault without a master key"),
	}

	randomID, _ := uuid.NewV4()
	vlt.UserID = &randomID

	vlt.MasterKeyID = nil
	vlt.ID = randomID

	success := vlt.Validate()
	if success {
		t.Error("failed! invalid vault was validated anyway!")
	}
}

func TestDeleteVault(t *testing.T) {
	vlt := &vault.Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("test vault"),
		Description:    common.StringOrNil("a test vault :D"),
	}

	randomID, _ := uuid.NewV4()
	vlt.UserID = &randomID

	success := vlt.Create(vaultDB)
	if !success {
		t.Errorf("failed to create vault %s", *vlt.Errors[0].Message)
		return
	}

	if vlt.MasterKeyID == nil {
		t.Errorf("failed to resolve master key for vault %s", vlt.ID)
		return
	}

	success = vlt.Delete((vaultDB))
	if !success {
		t.Errorf("failed to delete vault %s", *vlt.Errors[0].Message)
		return
	}
}

func TestDeleteVaultWithNoID(t *testing.T) {
	vlt := &vault.Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("test vault"),
		Description:    common.StringOrNil("a test vault :D"),
	}

	randomID, _ := uuid.NewV4()
	vlt.UserID = &randomID

	success := vlt.Create(vaultDB)
	if !success {
		t.Errorf("failed to create vault %s", *vlt.Errors[0].Message)
		return
	}

	if vlt.MasterKeyID == nil {
		t.Errorf("failed to resolve master key for vault %s", vlt.ID)
		return
	}

	vlt.ID = uuid.Nil
	success = vlt.Delete((vaultDB))
	if success {
		t.Errorf("deleted vault with no ID!")
		return
	}
}

func TestDeleteVaultWithKeys(t *testing.T) {
	vlt := &vault.Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("test vault"),
		Description:    common.StringOrNil("a test vault :D"),
	}

	randomID, _ := uuid.NewV4()
	vlt.UserID = &randomID

	success := vlt.Create(vaultDB)
	if !success {
		t.Errorf("failed to create vault %s", *vlt.Errors[0].Message)
		return
	}

	key := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s", vlt.ID)
		return
	}

	t.Logf("created ed25519 key with ID %s", key.ID)

	success = vlt.Delete((vaultDB))
	if !success {
		t.Errorf("failed to delete vault %s", *vlt.Errors[0].Message)
		return
	}

	t.Logf("deleted vault with ID %s", vlt.ID)

	newKey := vault.Ed25519Factory(keyDB, &vlt.ID, "test key", "just some key :D")
	if newKey != nil {
		t.Errorf("created Ed25519 keypair for deleted vault: %s %s", vlt.ID, *newKey.Errors[0].Message)
		return
	}
	if newKey == nil {
		t.Logf("couldn't create key for deleted vault %s", vlt.ID)
	}

	//is the key still present?
}

func TestGetVaults(t *testing.T) {
	for _, assn := range []string{"application", "organization", "user"} {
		vlt := &vault.Vault{
			ApplicationID:  nil,
			OrganizationID: nil,
			UserID:         nil,
			Name:           common.StringOrNil("test vault"),
			Description:    common.StringOrNil("a test vault :D"),
		}

		associationUUID, _ := uuid.NewV4() // just use a random uuid to represent the app, org or user association under test

		switch assn {
		case "application":
			vlt.ApplicationID = &associationUUID
		case "organization":
			vlt.OrganizationID = &associationUUID
		case "user":
			vlt.UserID = &associationUUID
		}
		vlt.Create(vaultDB)
		t.Logf("created vault %s for %s ID %s", vlt.ID, assn, associationUUID)

		switch assn {
		case "application":
			appVaults := vault.GetApplicationVaults(vlt.ApplicationID)
			if len(appVaults) != 1 {
				t.Errorf("couldn't retrieve vault for application ID %s", vlt.ApplicationID)
				return
			}
			t.Logf("found %d vaults for application ID %s", len(appVaults), vlt.ApplicationID)
		case "organization":
			orgVaults := vault.GetOrganizationVaults(vlt.OrganizationID)
			if len(orgVaults) != 1 {
				t.Errorf("couldn't retrieve vault for organisation ID %s", vlt.OrganizationID)
				return
			}
			t.Logf("found %d vaults for organization ID %s", len(orgVaults), vlt.OrganizationID)
		case "user":
			userVaults := vault.GetUserVaults(vlt.UserID)
			if len(userVaults) != 1 {
				t.Errorf("couldn't retrieve vault for User ID %s", vlt.UserID)
				return
			}
			t.Logf("found %d vaults for user ID %s", len(userVaults), vlt.UserID)
		}

	}
}

func TestCreateVault(t *testing.T) {
	for _, assn := range []string{"application", "organization", "user"} {
		vlt := &vault.Vault{
			ApplicationID:  nil,
			OrganizationID: nil,
			UserID:         nil,
			Name:           common.StringOrNil("test vault"),
			Description:    common.StringOrNil("a test vault :D"),
		}

		associationUUID, _ := uuid.NewV4() // just use a random uuid to represent the app, org or user association under test

		switch assn {
		case "application":
			vlt.ApplicationID = &associationUUID
		case "organization":
			vlt.OrganizationID = &associationUUID
		case "user":
			vlt.UserID = &associationUUID
		}

		success := vlt.Create(vaultDB)
		if !success {
			t.Errorf("failed to create vault with %s association! %s", assn, *vlt.Errors[0].Message)
			continue
		}

		common.Log.Debugf("created vault with %s association: %s", assn, vlt.ID)

		// it should have a master key...
		masterKey := vlt.MasterKey
		if masterKey == nil {
			t.Errorf("failed! master key was not set for the new %s-associated vault!", assn)
			continue
		}
		// the master key should be persisted
		if masterKey.ID == uuid.Nil {
			t.Errorf("failed! master key was not persisted for the new %s-associated vault!", assn)
			continue
		}
		// the master key should be AES-256-GCM
		if masterKey.Spec == nil || *masterKey.Spec != vault.KeySpecAES256GCM {
			t.Errorf("failed! master key spec was not set to AES-256-GCM for the new %s-associated vault!", assn)
			continue
		}
	}
}

func TestDeleteVaultNilDB(t *testing.T) {
	vlt := &vault.Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("test vault"),
		Description:    common.StringOrNil("a test vault :D"),
	}

	randomID, _ := uuid.NewV4()
	vlt.UserID = &randomID

	success := vlt.Create(vaultDB)
	if !success {
		t.Errorf("failed to create vault %s", *vlt.Errors[0].Message)
		return
	}

	if vlt.MasterKeyID == nil {
		t.Errorf("failed to resolve master key for vault %s", vlt.ID)
		return
	}

	success = vlt.Delete(nil)
	if !success {
		t.Errorf("failed to delete vault %s", *vlt.Errors[0].Message)
		return
	}
}

func TestGetVault(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	organizationId := vlt.OrganizationID

	dbVault := vault.GetVault(vlt.ID.String(), nil, organizationId, nil)
	if dbVault == nil {
		t.Errorf("failed to retrieve created vault from DB, vault ID %s", dbVault.ID)
		return
	}
	if dbVault.ID != vlt.ID {
		t.Errorf("incorrect vault returned, expected vault ID %s, got vault ID %s", vlt.ID, dbVault.ID)
		return
	}
}

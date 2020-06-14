package vault

import (
	"fmt"
	"testing"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	vaulttestpgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
)

func init() {
	vaulttestpgputil.RequirePGP()
}

var vaultDB = dbconf.DatabaseConnection()

func vaultFactory() *Vault {
	associationUUID, _ := uuid.NewV4()

	vault := &Vault{
		ApplicationID:  nil,
		OrganizationID: &associationUUID,
		UserID:         nil,
		Name:           common.StringOrNil(fmt.Sprintf("vault@%d", time.Now().Unix())),
		Description:    common.StringOrNil("a test vault for key unit tests"),
	}

	if vault.Create(vaultDB) {
		return vault
	}

	return nil
}

func TestCreateVaultFailsWithoutValidAssociation(t *testing.T) {
	vault := &Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("invalid vault"),
		Description:    common.StringOrNil("a test vault with invalid app, org or user association"),
	}

	success := vault.Create(vaultDB)
	if success || vault.ID != uuid.Nil {
		t.Error("failed! invalid vault was created anyway!")
	}
}

func TestDeleteVault(t *testing.T) {
	vault := &Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("test vault"),
		Description:    common.StringOrNil("a test vault :D"),
	}

	randomID, _ := uuid.NewV4()
	vault.UserID = &randomID

	success := vault.Create(vaultDB)
	if !success {
		t.Errorf("failed to create vault %s", *vault.Errors[0].Message)
		return
	}

	key, err := vault.resolveMasterKey(vaultDB)
	if key == nil {
		t.Errorf("failed to resolve master key for vault %s, error %s", vault.ID, err.Error())
		return
	}

	success = vault.Delete((vaultDB))
	if !success {
		t.Errorf("failed to delete vault %s", *vault.Errors[0].Message)
		return
	}
}

func TestDeleteVaultWithKeys(t *testing.T) {
	vault := &Vault{
		ApplicationID:  nil,
		OrganizationID: nil,
		UserID:         nil,
		Name:           common.StringOrNil("test vault"),
		Description:    common.StringOrNil("a test vault :D"),
	}

	randomID, _ := uuid.NewV4()
	vault.UserID = &randomID

	success := vault.Create(vaultDB)
	if !success {
		t.Errorf("failed to create vault %s", *vault.Errors[0].Message)
		return
	}

	key := ed25519Factory(&vault.ID)
	if key == nil {
		t.Errorf("failed to create Ed25519 keypair for vault: %s! %s", vault.ID, *key.Errors[0].Message)
		return
	}

	t.Logf("created ed25519 key with ID %s", key.ID)

	success = vault.Delete((vaultDB))
	if !success {
		t.Errorf("failed to delete vault %s", *vault.Errors[0].Message)
		return
	}

	t.Logf("deleted vault with ID %s", vault.ID)

	newKey := ed25519Factory(&vault.ID)
	if newKey != nil {
		t.Errorf("created Ed25519 keypair for deleted vault: %s! %s", vault.ID, *newKey.Errors[0].Message)
		return
	}
	if newKey == nil {
		t.Logf("couldn't create key for deleted vault %s", vault.ID)
	}

	//is the key still present?
}

func TestGetVaults(t *testing.T) {
	for _, assn := range []string{"application", "organization", "user"} {
		vault := &Vault{
			ApplicationID:  nil,
			OrganizationID: nil,
			UserID:         nil,
			Name:           common.StringOrNil("test vault"),
			Description:    common.StringOrNil("a test vault :D"),
		}

		associationUUID, _ := uuid.NewV4() // just use a random uuid to represent the app, org or user association under test

		switch assn {
		case "application":
			vault.ApplicationID = &associationUUID
		case "organization":
			vault.OrganizationID = &associationUUID
		case "user":
			vault.UserID = &associationUUID
		}
		vault.Create(vaultDB)
		t.Logf("created vault %s for %s ID %s", vault.ID, assn, associationUUID)

		switch assn {
		case "application":
			appVaults := GetApplicationVaults(vault.ApplicationID)
			if len(appVaults) != 1 {
				t.Errorf("couldn't retrieve vault for application ID %s", vault.ApplicationID)
				return
			}
			t.Logf("found %d vaults for application ID %s", len(appVaults), vault.ApplicationID)
		case "organization":
			orgVaults := GetOrganizationVaults(vault.OrganizationID)
			if len(orgVaults) != 1 {
				t.Errorf("couldn't retrieve vault for organisation ID %s", vault.OrganizationID)
				return
			}
			t.Logf("found %d vaults for organization ID %s", len(orgVaults), vault.OrganizationID)
		case "user":
			userVaults := GetUserVaults(vault.UserID)
			if len(userVaults) != 1 {
				t.Errorf("couldn't retrieve vault for User ID %s", vault.UserID)
				return
			}
			t.Logf("found %d vaults for user ID %s", len(userVaults), vault.UserID)
		}

	}
}

func TestCreateVault(t *testing.T) {
	for _, assn := range []string{"application", "organization", "user"} {
		vault := &Vault{
			ApplicationID:  nil,
			OrganizationID: nil,
			UserID:         nil,
			Name:           common.StringOrNil("test vault"),
			Description:    common.StringOrNil("a test vault :D"),
		}

		associationUUID, _ := uuid.NewV4() // just use a random uuid to represent the app, org or user association under test

		switch assn {
		case "application":
			vault.ApplicationID = &associationUUID
		case "organization":
			vault.OrganizationID = &associationUUID
		case "user":
			vault.UserID = &associationUUID
		}

		success := vault.Create(vaultDB)
		if !success {
			t.Errorf("failed to create vault with %s association! %s", assn, *vault.Errors[0].Message)
			continue
		}

		common.Log.Debugf("created vault with %s association: %s", assn, vault.ID)

		// it should have a master key...
		masterKey := vault.MasterKey
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
		if masterKey.Spec == nil || *masterKey.Spec != keySpecAES256GCM {
			t.Errorf("failed! master key spec was not set to AES-256-GCM for the new %s-associated vault!", assn)
			continue
		}
	}
}

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

	vault.Create(vaultDB)
	return vault
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

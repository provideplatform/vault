package vault

import (
	"encoding/hex"
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	vaultcrypto "github.com/provideapp/vault/vault/crypto"
	provide "github.com/provideservices/provide-go"
)

// Vault provides secure key management
type Vault struct {
	provide.Model

	// Associations
	ApplicationID  *uuid.UUID `sql:"type:uuid" json:"-"`
	OrganizationID *uuid.UUID `sql:"type:uuid" json:"-"`
	UserID         *uuid.UUID `sql:"type:uuid" json:"-"`

	Name        *string `json:"name"`
	Description *string `json:"description"`

	MasterKey   *Key       `sql:"-" json:"master_key"`
	MasterKeyID *uuid.UUID `sql:"type:uuid" json:"master_key_id"`
}

// ListKeysQuery returns the fields to SELECT from vault keys table
func (v *Vault) ListKeysQuery(db *gorm.DB) *gorm.DB {
	return db.Select("keys.id, keys.created_at, keys.name, keys.description, keys.type, keys.usage, keys.spec, keys.seed, keys.private_key, keys.public_key, keys.vault_id").Where("keys.vault_id = ?", v.ID)
}

// ListSecretsQuery returns the fields to SELECT from vault secrets table
func (v *Vault) ListSecretsQuery(db *gorm.DB) *gorm.DB {
	return db.Select("secrets.id, secrets.created_at, secrets.name, secrets.description, secrets.type").Where("secrets.vault_id = ?", v.ID)
}

func (v *Vault) resolveMasterKey(db *gorm.DB) (*Key, error) {
	if v.MasterKeyID == nil {
		return nil, fmt.Errorf("unable to resolve master key for vault: %s; nil master key id", v.ID)
	}

	masterKey := &Key{}
	db.Where("id = ?", v.MasterKeyID).Find(&masterKey)
	if masterKey == nil || masterKey.ID == uuid.Nil {
		return nil, fmt.Errorf("failed to resolve master key for vault: %s", v.ID)
	}
	masterKey.setEncrypted(true)

	v.MasterKey = masterKey
	v.MasterKeyID = &masterKey.ID
	return v.MasterKey, nil
}

func (v *Vault) validate() bool {
	v.Errors = make([]*provide.Error, 0)

	if v.ApplicationID == nil && v.OrganizationID == nil && v.UserID == nil {
		v.Errors = append(v.Errors, &provide.Error{
			Message: common.StringOrNil("must be associated with an application, organization or user"),
		})
	}

	if v.ID != uuid.Nil && v.MasterKeyID == nil {
		v.Errors = append(v.Errors, &provide.Error{
			Message: common.StringOrNil("master key required"),
		})
	}

	return len(v.Errors) == 0
}

func (v *Vault) createMasterKey(tx *gorm.DB) error {
	keypair, err := vaultcrypto.CreatePair(vaultcrypto.PrefixByteSeed)
	if err != nil {
		common.Log.Warningf("failed to create Ed25519 keypair; %s", err.Error())
		return err
	}

	seed, err := keypair.Seed()
	if err != nil {
		common.Log.Warningf("failed to read encoded Ed25519 seed; %s", err.Error())
		return err
	}

	masterKey := &Key{
		VaultID:     &v.ID,
		Type:        common.StringOrNil(keyTypeSymmetric),
		Usage:       common.StringOrNil(keyUsageEncryptDecrypt),
		Spec:        common.StringOrNil(keySpecAES256GCM),
		Name:        common.StringOrNil(fmt.Sprintf("master0")),
		Description: common.StringOrNil(fmt.Sprintf("AES-256 GCM master key for vault %s", v.ID)),
		PrivateKey:  common.StringOrNil(string(seed[0:32])),
	}

	if !masterKey.Create(tx) {
		err := fmt.Errorf("failed to create master key for vault: %s; %s", v.ID, *masterKey.Errors[0].Message)
		common.Log.Warning(err.Error())
		return err
	}

	v.MasterKey = masterKey
	v.MasterKeyID = &masterKey.ID
	tx.Save(&v)

	common.Log.Debugf("created master key %s with %d-byte seed for vault: %s", masterKey.ID, len(seed), v.ID)
	return nil
}

// Create and persist a vault
func (v *Vault) Create(tx *gorm.DB) bool {
	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
	}

	if !v.validate() {
		return false
	}

	if db.NewRecord(v) {
		result := db.Create(&v)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				v.Errors = append(v.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(v) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created vault %s", v.ID.String())
				err := v.createMasterKey(db)
				if err != nil {
					common.Log.Warningf("failed to create master key for vault: %s; %s", v.ID.String(), err.Error())
				}

				return success
			}
		}
	}

	return false
}

// CreateC25519Keypair creates an c25519 keypair suitable for Diffie-Hellman key exchange
func (v *Vault) CreateC25519Keypair(name, description string, ephemeral bool) (*Key, error) {
	publicKey, privateKey, err := provide.C25519GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create C25519 keypair; %s", err.Error())
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	c25519Key := &Key{
		VaultID:     &v.ID,
		Type:        common.StringOrNil(keyTypeAsymmetric),
		Usage:       common.StringOrNil(keyUsageSignVerify),
		Spec:        common.StringOrNil(keySpecECCC25519),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		PublicKey:   common.StringOrNil(publicKeyHex),
		PrivateKey:  common.StringOrNil(string(privateKey)),
	}

	if !ephemeral {
		db := dbconf.DatabaseConnection()
		if !c25519Key.Create(db) {
			return nil, fmt.Errorf("failed to create C25519 key in vault: %s; %s", v.ID, *c25519Key.Errors[0].Message)
		}

		common.Log.Debugf("created C25519 key %s in vault: %s; public key: %s", c25519Key.ID, v.ID, publicKeyHex)
	}

	return c25519Key, nil
}

// Delete a vault
func (v *Vault) Delete(tx *gorm.DB) bool {
	if v.ID == uuid.Nil {
		common.Log.Warning("attempted to delete vault instance")
		return false
	}

	var db *gorm.DB
	if tx != nil {
		db = tx
	} else {
		db = dbconf.DatabaseConnection()
		db = db.Begin()
		defer db.RollbackUnlessCommitted()
	}

	result := db.Delete(&v)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			v.Errors = append(v.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(v.Errors) == 0
	return success
}

// GetApplicationVaults - retrieve the vaults associated with the given application
func GetApplicationVaults(applicationID *uuid.UUID) []*Vault {
	var vaults []*Vault
	dbconf.DatabaseConnection().Where("application_id = ?", applicationID).Find(&vaults)
	return vaults
}

// GetOrganizationVaults - retrieve the vaults associated with the given organization
func GetOrganizationVaults(organizationID *uuid.UUID) []*Vault {
	var vaults []*Vault
	dbconf.DatabaseConnection().Where("organization_id = ?", organizationID).Find(&vaults)
	return vaults
}

package vault

import (
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go/api"
	vaultcrypto "github.com/provideapp/vault/crypto"
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

	MasterKey   *Key       `sql:"-" json:"-"`
	MasterKeyID *uuid.UUID `sql:"type:uuid" json:"-"`
}

// InfinityKey is the encryption/decryption key for the vault keys
// which are used to decrypt the private keys/seeds
// initial implementation has this unencrypted in memory
// secondary implementation will encrypt this with derived key (or similar)
var InfinityKey *[]byte

// CloakingKey will ensure Infinity Key is encrypted in memory until required
var CloakingKey *[]byte

// SealUnsealRequest provides the seal/unseal information
type SealUnsealRequest struct {
	UnsealKey *string `json:"unseal,omitempty"`
	SealKey   *string `json:"seal,omitempty"`
}

// ListKeysQuery returns the fields to SELECT from vault keys table
func (v *Vault) ListKeysQuery(db *gorm.DB) *gorm.DB {
	return db.Select("keys.id, keys.created_at, keys.name, keys.description, keys.type, keys.usage, keys.spec, keys.seed, keys.private_key, keys.public_key, keys.vault_id").Where("keys.vault_id = ?", v.ID)
}

// ListSecretsQuery returns the fields to SELECT from vault secrets table
func (v *Vault) ListSecretsQuery(db *gorm.DB) *gorm.DB {
	return db.Select("secrets.id, secrets.created_at, secrets.vault_id, secrets.name, secrets.value, secrets.description, secrets.type").Where("secrets.vault_id = ?", v.ID)
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

// Validate the vault
func (v *Vault) Validate() bool {
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
	masterKey := &Key{
		VaultID:     &v.ID,
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
		Spec:        common.StringOrNil(KeySpecAES256GCM),
		Name:        common.StringOrNil(defaultVaultMasterKeyName),
		Description: common.StringOrNil(fmt.Sprintf("AES-256-GCM master key for vault %s", v.ID)),
	}

	if !masterKey.createPersisted(tx) {
		err := fmt.Errorf("failed to create master key for vault: %s; %s", v.ID, *masterKey.Errors[0].Message)
		return err
	}

	v.MasterKey = masterKey
	v.MasterKeyID = &masterKey.ID
	tx.Save(&v)

	common.Log.Debugf("created master key %s for vault: %s", masterKey.ID, v.ID)
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

	if !v.Validate() {
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

// Delete a vault
func (v *Vault) Delete(tx *gorm.DB) bool {
	if v.ID == uuid.Nil {
		common.Log.Warning("attempted to delete vault instance which only exists in-memory")
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

// GetUserVaults - retrieve the vaults associated with the given user
func GetUserVaults(userID *uuid.UUID) []*Vault {
	var vaults []*Vault
	dbconf.DatabaseConnection().Where("user_id = ?", userID).Find(&vaults)
	return vaults
}

<<<<<<< HEAD
// GetVaults - retrieve the vaults for the specified parameters
// not used for the moment - paginate refactoring needed
func GetVaults(applicationID, organizationID, userID *uuid.UUID) []*Vault {
	var vaults []*Vault
	var query *gorm.DB

	db := dbconf.DatabaseConnection()
	if applicationID != nil && *applicationID != uuid.Nil {
		query = db.Where("vaults.application_id = ?", applicationID)
	} else if organizationID != nil && *organizationID != uuid.Nil {
		query = db.Where("vaults.organization_id = ?", organizationID)
	} else if userID != nil && *userID != uuid.Nil {
		query = db.Where("vaults.user_id = ?", userID)
	}
	query.Find(&vaults)

	return vaults
}

// GetVault returns a vault for the specified parameters
func GetVault(vaultID string, applicationID, organizationID, userID *uuid.UUID) *Vault {
	// Set up the database connection
	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	var vault = &Vault{}

	query = db.Where("id = ?", vaultID)
	if applicationID != nil && *applicationID != uuid.Nil {
		query = query.Where("vaults.application_id = ?", applicationID)
	} else if organizationID != nil && *organizationID != uuid.Nil {
		query = query.Where("vaults.organization_id = ?", organizationID)
	} else if userID != nil && *userID != uuid.Nil {
		query = query.Where("vaults.user_id = ?", userID)
	}
	query.Find(&vault)

	return vault
}

// GetVaultKey returns a vault key for the specified parameters
func GetVaultKey(keyID, vaultID string, applicationID, organizationID, userID *uuid.UUID) *Key {
	// Set up the database connection
	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	var key = &Key{}

	query = db.Table("keys")
	query = query.Joins("inner join vaults on keys.vault_id = vaults.id")
	query = query.Where("keys.id = ? AND keys.vault_id = ?", keyID, vaultID)
	if applicationID != nil && *applicationID != uuid.Nil {
		query = query.Where("vaults.application_id = ?", applicationID)
	} else if organizationID != nil && *organizationID != uuid.Nil {
		query = query.Where("vaults.organization_id = ?", organizationID)
	} else if userID != nil && *userID != uuid.Nil {
		query = query.Where("vaults.user_id = ?", userID)
	}
	query.Find(&key)

	return key
}

// GetVaultSecret returns a vault secret for the specified parameters
func GetVaultSecret(secretID, vaultID string, applicationID, organizationID, userID *uuid.UUID) *Secret {
	// Set up the database connection
	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	var secret = &Secret{}

	query = db.Table("secrets")
	query = query.Joins("inner join vaults on secrets.vault_id = vaults.id")
	query = query.Where("secrets.id = ? AND secrets.vault_id = ?", secretID, vaultID)
	if applicationID != nil && *applicationID != uuid.Nil {
		query = query.Where("vaults.application_id = ?", applicationID)
	} else if organizationID != nil && *organizationID != uuid.Nil {
		query = query.Where("vaults.organization_id = ?", organizationID)
	} else if userID != nil && *userID != uuid.Nil {
		query = query.Where("vaults.user_id = ?", userID)
	}
	query.Find(&secret)

	return secret
=======
// SetInfinityKey sets the Infinity Key
func SetInfinityKey(key *[]byte) error {
	if key == nil {
		return fmt.Errorf("error unsealing vault (100)")
	}

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault (200)")
	}

	// set the cloaking key to this random key
	CloakingKey = &randomKey

	// conver the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = &randomKey

	// encrypt the infinity key with the cloaking key
	infinityKey, err := cloakingKey.Encrypt(*key, nil)
	if err != nil {
		return fmt.Errorf("error unsealing vault (300)")
	}
	InfinityKey = &infinityKey
	return nil
}

func getInfinityKey() (*[]byte, error) {
	if CloakingKey == nil {
		return nil, fmt.Errorf("error unsealing vault (400)")
	}

	// convert the cloaking key into an AES key
	cloakingKey := vaultcrypto.AES256GCM{}
	cloakingKey.PrivateKey = CloakingKey

	// decrypt the infinity key with the cloaking key
	encryptedInfinityKey := *InfinityKey

	infinityKey, err := cloakingKey.Decrypt(encryptedInfinityKey[NonceSizeSymmetric:], encryptedInfinityKey[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault (500)")
	}

	return &infinityKey, nil
}

// seal encrypts the unsealed material with the infinity key
func seal(unsealedKey *[]byte) (*[]byte, error) {
	if InfinityKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}

	if unsealedKey == nil || *unsealedKey == nil {
		return nil, fmt.Errorf("nothing to seal")
	}

	var err error
	sealerKey := vaultcrypto.AES256GCM{}
	sealerKey.PrivateKey, err = getInfinityKey()
	if err != nil {
		return nil, fmt.Errorf("error sealing vault %s", err.Error())
	}
	sealedKey, err := sealerKey.Encrypt(*unsealedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error while sealing")
	}

	return &sealedKey, nil
}

// unseal decrypts the sealed material with the infinity key
func unseal(sealedKey *[]byte) (*[]byte, error) {
	if InfinityKey == nil {
		return nil, fmt.Errorf("vault is sealed")
	}
	if sealedKey == nil || *sealedKey == nil {
		return nil, fmt.Errorf("nothing to unseal")
	}

	var err error
	unsealerKey := vaultcrypto.AES256GCM{}
	unsealerKey.PrivateKey, err = getInfinityKey()
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault %s", err.Error())
	}
	encryptedData := *sealedKey
	unsealedKey, err := unsealerKey.Decrypt(encryptedData[NonceSizeSymmetric:], encryptedData[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error while unsealing")
	}
	return &unsealedKey, nil
>>>>>>> refactoring + master key encryption
}

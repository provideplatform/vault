package vault

import (
	"fmt"
	"sync"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go"
)

// Secret represents a secret encrypted by the vault's master key
type Secret struct {
	provide.Model
	VaultID     *uuid.UUID `sql:"not null;type:uuid" json:"vault_id"`
	Type        *string    `sql:"not null" json:"type"` // arbitrary secret type
	Name        *string    `sql:"not null" json:"name"`
	Description *string    `json:"description"`
	Data        *[]byte    `sql:"type:bytea" json:"-"`
	encrypted   *bool      `sql:"-"`
	mutex       sync.Mutex `sql:"-"`
	vault       *Vault     `sql:"-"` // vault cache
}

// SecretStoreRetrieveRequestResponse represents the API request/response parameters
// needed to store or retrieve a secret
type SecretStoreRetrieveRequestResponse struct {
	Data        *[]byte `json:"secret,omitempty"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

func (s *Secret) validate() bool {
	s.Errors = make([]*provide.Error, 0)

	if s.Name == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("secret name required"),
		})
	}

	if s.Type == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("secret type required"),
		})
	}

	if s.Data == nil || len(*s.Data) == 0 {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("secret data required"),
		})
	}

	return len(s.Errors) == 0
}

// Store saves a secret encrypted (with the vault master key) in the database
func (s *Secret) Store() (*[]byte, error) {

	if !s.validate() {
		return nil, fmt.Errorf("invalid secret: name, type and data required")
	}

	db := dbconf.DatabaseConnection()

	if s.encrypted == nil || !*s.encrypted {
		err := s.encryptFields()
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key material; %s", err.Error())
		}
	}

	success := s.save(db)
	if success {
		common.Log.Debugf("saved secret to db with id: %s", s.ID.String())
	}
	return s.Data, nil
}

// Retrieve saves a secret encrypted (with the vault master key) in the database
func (s *Secret) Retrieve() (*[]byte, error) {

	if s.encrypted == nil || *s.encrypted {
		err := s.decryptFields()
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret material; %s", err.Error())
		}
	}
	return s.Data, nil
}

// Create and persist a key
func (s *Secret) save(db *gorm.DB) bool {

	if db.NewRecord(s) {
		result := db.Create(&s)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				s.Errors = append(s.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(s) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created secret %s (%s) in vault %s", *s.Name, s.ID.String(), s.VaultID.String())
				return success
			}
		}
	}

	return false
}

// TODO refactor this so the code isn't repeated across secrets and keys
func (s *Secret) resolveMasterKey(db *gorm.DB) (*Key, error) {
	err := s.resolveVault(db)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault for master key resolution without vault id for key: %s", s.ID)
	}

	if s.vault == nil || s.vault.ID == uuid.Nil {
		return nil, fmt.Errorf("failed to resolve master key without vault id for key: %s", s.ID)
	}

	if s.vault.MasterKeyID != nil && s.vault.MasterKeyID.String() == s.ID.String() {
		return nil, fmt.Errorf("unable to resolve master key: %s; current key is master; vault id: %s", s.ID, s.VaultID)
	}

	masterKey, err := s.vault.resolveMasterKey(db)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve master key for key: %s; %s", s.ID, err.Error())
	}

	return masterKey, err
}

// TODO refactor this so the code isn't repeated across secrets and keys
func (s *Secret) resolveVault(db *gorm.DB) error {
	if s.VaultID == nil {
		return fmt.Errorf("unable to resolve vault without id for secret: %s", s.ID)
	}

	if s.vault != nil {
		common.Log.Tracef("resolved cached pointer to vault %s within local key %s", s.vault.ID, s.ID)
		return nil
	}

	vlt := &Vault{}
	db.Where("id = ?", s.VaultID).Find(&vlt)
	if vlt == nil || vlt.ID == uuid.Nil {
		return fmt.Errorf("failed to resolve master key; no vault found for key: %s; vault id: %s", s.ID, s.VaultID)
	}
	s.vault = vlt

	return nil
}

// TODO refactor this so it isn't repeated across keys and secrets...
func (s *Secret) setEncrypted(encrypted bool) {
	s.encrypted = &encrypted
}

// TODO refactor this so it isn't repeated across keys and secrets...
func (s *Secret) encryptFields() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.encrypted == nil {
		s.setEncrypted(s.ID != uuid.Nil)
	}

	if *s.encrypted {
		return fmt.Errorf("fields already encrypted for secret: %s", s.ID)
	}

	masterKey, err := s.resolveMasterKey(dbconf.DatabaseConnection())
	if err != nil {
		common.Log.Tracef("encrypting master key fields for vault: %s", s.VaultID)

		if masterKey.Seed != nil {
			seed, err := pgputil.PGPPubEncrypt(*masterKey.Seed)
			if err != nil {
				return err
			}
			masterKey.Seed = &seed
		}

		if masterKey.PrivateKey != nil {
			privateKey, err := pgputil.PGPPubEncrypt(*masterKey.PrivateKey)
			if err != nil {
				return err
			}
			masterKey.PrivateKey = &privateKey
		}
	} else {
		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if s.Data != nil {
			encryptedSecret, err := masterKey.Encrypt(*s.Data, nil)
			if err != nil {
				return err
			}
			s.Data = &encryptedSecret
		}
	}

	s.setEncrypted(true)
	return nil
}

func (s *Secret) decryptFields() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.encrypted == nil {
		s.setEncrypted(s.ID != uuid.Nil)
	}

	if !*s.encrypted {
		return fmt.Errorf("fields already decrypted for secret: %s", s.ID)
	}

	masterKey, err := s.resolveMasterKey(dbconf.DatabaseConnection())
	if err != nil {
		common.Log.Tracef("decrypting master key fields for vault: %s", s.VaultID)

		if s.Data != nil {
			decryptedData, err := pgputil.PGPPubDecrypt([]byte(*s.Data))
			if err != nil {
				return err
			}
			s.Data = &decryptedData
		}
	} else {
		common.Log.Tracef("decrypting secret fields with master key %s for vault: %s", masterKey.ID, s.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()
		if s.Data != nil {
			decryptedData, err := masterKey.Decrypt(*s.Data)
			if err != nil {
				return err
			}
			s.Data = &decryptedData
		}
	}

	s.setEncrypted(false)
	return nil
}

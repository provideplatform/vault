package vault

import (
	"fmt"
	"sync"
	"time"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go/api"
)

// MaxSecretLengthInBytes is the maximum allowable length of a secret to be stored
const MaxSecretLengthInBytes = 4096

// Secret represents a secret encrypted by the vault's master key
type Secret struct {
	provide.Model
	VaultID        *uuid.UUID `sql:"not null;type:uuid" json:"vault_id"`
	Type           *string    `sql:"not null" json:"type"` // arbitrary secret type
	Name           *string    `sql:"not null" json:"name"`
	Description    *string    `json:"description"`
	Value          *[]byte    `sql:"type:bytea" json:"-"`
	DecryptedValue *string    `sql:"-" json:"value,omitempty"`
	encrypted      *bool      `sql:"-"`
	mutex          sync.Mutex `sql:"-"`
	vault          *Vault     `sql:"-"` // vault cache
}

// SecretResponse represents a secret response which has the decrypted value
type SecretResponse struct {
	ID        uuid.UUID        `json:"id"`
	CreatedAt time.Time        `json:"created_at"`
	Errors    []*provide.Error `json:"-"`

	VaultID     *uuid.UUID `json:"vault_id"`
	Type        *string    `json:"type"`
	Name        *string    `json:"name"`
	Description *string    `json:"description"`
	Value       *string    `json:"value"`
}

// Validate ensures that all required fields are present
func (s *Secret) validate() bool {
	s.Errors = make([]*provide.Error, 0)

	if s.Name == nil || common.StringOrNil(*s.Name) == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("name required"),
		})
	}

	if s.Type == nil || common.StringOrNil(*s.Type) == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("type required"),
		})
	}

	if s.DecryptedValue == nil || len(*s.DecryptedValue) == 0 {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("value required"),
		})
	}

	if s.DecryptedValue != nil && len(*s.DecryptedValue) > MaxSecretLengthInBytes {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("value too long"),
		})
	}

	return len(s.Errors) == 0
}

// Create encrypts (i.e., with the vault master key) and stores the secret in the database
func (s *Secret) Create(db *gorm.DB) bool {
	if !s.validate() {
		return false
	}

	valueAsBytes := []byte(*s.DecryptedValue)
	s.Value = &valueAsBytes
	s.DecryptedValue = nil

	if s.encrypted == nil || !(*s.encrypted) {
		err := s.encryptFields()
		if err != nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("failed to encrypt key material; %s", err.Error())),
			})
			return false
		}
	}

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
				common.Log.Debugf("saved secret to db with id: %s", s.ID.String())
				s.Value = nil
			}
			return success
		}
	}

	return false
}

// AsResponse returns a Secret, with its value decrypted using the vault master key
func (s *Secret) AsResponse() (*SecretResponse, error) {
	if s.encrypted == nil || *s.encrypted {
		err := s.decryptFields()
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret material; %s", err.Error())
		}
	}

	decryptedValue := *s.Value
	decryptedValueAsString := string(decryptedValue[:])
	s.Value = nil

	return &SecretResponse{
		ID:          s.ID,
		CreatedAt:   s.CreatedAt,
		VaultID:     s.VaultID,
		Type:        s.Type,
		Name:        s.Name,
		Description: s.Description,
		Value:       &decryptedValueAsString,
	}, nil
}

// Delete removes a secret from the database
func (s *Secret) Delete(db *gorm.DB) bool {
	if s.ID == uuid.Nil {
		common.Log.Warning("attempted to delete secret instance which only exists in-memory")
		return false
	}

	result := db.Delete(&s)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(s.Errors) == 0
	return success
}

// TODO refactor this so the code isn't repeated across secrets and keys
func (s *Secret) resolveMasterKey(db *gorm.DB) (*Key, error) {
	err := s.resolveVault(db)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault for master key resolution without vault id for secret: %s", s.ID)
	}

	if s.vault == nil || s.vault.ID == uuid.Nil {
		return nil, fmt.Errorf("failed to resolve master key without vault id for secret: %s", s.ID)
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
		return fmt.Errorf("failed to resolve master key; no vault found for secret: %s; vault id: %s", s.ID, s.VaultID)
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

		if s.Value != nil {
			encryptedSecret, err := masterKey.Encrypt(*s.Value, nil)
			if err != nil {
				return err
			}
			s.Value = &encryptedSecret
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

		if s.Value != nil {
			decryptedData, err := pgputil.PGPPubDecrypt([]byte(*s.Value))
			if err != nil {
				return err
			}
			s.Value = &decryptedData
		}
	} else {
		common.Log.Tracef("decrypting secret fields with master key %s for vault: %s", masterKey.ID, s.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()
		if s.Value != nil {
			decryptedData, err := masterKey.Decrypt(*s.Value)
			if err != nil {
				return err
			}
			s.Value = &decryptedData
		}
	}

	s.setEncrypted(false)
	return nil
}

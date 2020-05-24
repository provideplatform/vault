package vault

import (
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
	Data        *string    `sql:"type:bytea" json:"-"`
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

	if s.Data == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("secret data required"),
		})
	}

	return len(s.Errors) == 0
}

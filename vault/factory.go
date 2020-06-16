package vault

import (
	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
)

// New is a factory factory to create and persist vault instances
func New(
	db *gorm.DB,
	name, description string,
	applicationID, organizationID, userID *uuid.UUID,
) *Vault {
	vault := &Vault{
		ApplicationID:  applicationID,
		OrganizationID: organizationID,
		UserID:         userID,
		Name:           common.StringOrNil(name),
		Description:    common.StringOrNil(description),
	}

	if vault.Create(db) {
		return vault
	}

	return nil
}

// NewKey is a generic factory for creating and persisting new keys
func NewKey(
	db *gorm.DB,
	vaultID *uuid.UUID,
	name, description, keyType, keyUsage, keySpec string,
) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(keySpec),
		Type:        common.StringOrNil(keyType),
		Usage:       common.StringOrNil(keyUsage),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

// NewEphemeralKey is a generic factory for creating ephemeral keys
func NewEphemeralKey(
	vaultID *uuid.UUID,
	name, description, keyType, keyUsage, keySpec string,
) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(keySpec),
		Type:        common.StringOrNil(keyType),
		Usage:       common.StringOrNil(keyUsage),
	}

	err := key.create()
	if err != nil {
		common.Log.Warningf("failed to create ephemeral %s key; %s", keySpec, err.Error())
		return nil
	}
	return key
}

// AES256GCMFactory AES-256-GCM
func AES256GCMFactory(db *gorm.DB, vaultID *uuid.UUID, name, description string) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecAES256GCM),
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

// AES256GCMEphemeralFactory ephemeral AES-256-GCM
func AES256GCMEphemeralFactory(vaultID *uuid.UUID, name, description string) *Key {
	ephemeral := true

	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecAES256GCM),
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
		Ephemeral:   &ephemeral,
	}

	err := key.create()
	if err != nil {
		common.Log.Warningf("failed to create ephemeral AES-256-GCM key; %s", err.Error())
		return nil
	}

	return key
}

// BabyJubJubFactory babyJubJub curve
func BabyJubJubFactory(db *gorm.DB, vaultID *uuid.UUID, name, description string) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCBabyJubJub),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

// C25519Factory C25519
func C25519Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCC25519),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

// Chacha20Factory ChaCha-20
func Chacha20Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecChaCha20),
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

// Ed25519Factory Ed25519
func Ed25519Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCEd25519),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

// Secp256k1Factory secp256k1
func Secp256k1Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) *Key {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCSecp256k1),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil
	}

	return key
}

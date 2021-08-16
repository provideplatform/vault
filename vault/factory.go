package vault

import (
	"fmt"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
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
) (*Key, error) {

	boolTrue := true

	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(keySpec),
		Type:        common.StringOrNil(keyType),
		Usage:       common.StringOrNil(keyUsage),
		Ephemeral:   &boolTrue,
	}

	err := key.create()
	if err != nil {
		return nil, fmt.Errorf("Error creating new ephemeral %s key: %s", keySpec, err.Error())
	}
	return key, nil
}

// SecretFactory ....
func SecretFactory(db *gorm.DB, vaultID *uuid.UUID, secretcontents []byte, name, secretType, description string) (*Secret, error) {
	secret := &Secret{
		VaultID:        vaultID,
		Name:           common.StringOrNil(name),
		Description:    common.StringOrNil(description),
		Type:           common.StringOrNil(secretType),
		DecryptedValue: common.StringOrNil(string(secretcontents)),
	}

	if !secret.Create(db) {
		return nil, fmt.Errorf("Error(s) creating/persisting secret: %v", *secret.Errors[0].Message)
	}

	return secret, nil
}

// AES256GCMFactory AES-256-GCM
func AES256GCMFactory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecAES256GCM),
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecAES256GCM, *key.Errors[0].Message)
	}

	return key, nil
}

// AES256GCMEphemeralFactory ephemeral AES-256-GCM
func AES256GCMEphemeralFactory(vaultID *uuid.UUID, name, description string) (*Key, error) {
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
		return nil, fmt.Errorf("error creating ephemeral %skey: %s", KeySpecAES256GCM, err.Error())
	}

	return key, nil
}

// BabyJubJubFactory babyJubJub curve
func BabyJubJubFactory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCBabyJubJub),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecECCBabyJubJub, *key.Errors[0].Message)
	}

	return key, nil
}

// C25519Factory C25519
func C25519Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCC25519),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecECCC25519, *key.Errors[0].Message)
	}

	return key, nil
}

// Chacha20Factory ChaCha-20
func Chacha20Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecChaCha20),
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecChaCha20, *key.Errors[0].Message)
	}

	return key, nil
}

// Ed25519Factory Ed25519
func Ed25519Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCEd25519),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecECCEd25519, *key.Errors[0].Message)
	}

	return key, nil
}

// Ed25519NKeyFactory Ed25519-nkey
func Ed25519NKeyFactory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCEd25519NKey),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecECCEd25519, *key.Errors[0].Message)
	}

	return key, nil
}

// Secp256k1Factory secp256k1
func Secp256k1Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCSecp256k1),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecECCSecp256k1, *key.Errors[0].Message)
	}

	return key, nil
}

// EthHDWalletFactory secp256k1 HD wallet for deriving ETH keys/addresses
func EthHDWalletFactory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecECCBIP39),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecECCBIP39, *key.Errors[0].Message)
	}

	return key, nil
}

// RSA4096Factory RSA 4096-bit
func RSA4096Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecRSA4096),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecRSA4096, *key.Errors[0].Message)
	}

	return key, nil
}

// RSA3072Factory RSA 3072-bit
func RSA3072Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecRSA3072),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecRSA3072, *key.Errors[0].Message)
	}

	return key, nil
}

// RSA2048Factory RSA 2048-bit
func RSA2048Factory(db *gorm.DB, vaultID *uuid.UUID, name, description string) (*Key, error) {
	key := &Key{
		VaultID:     vaultID,
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Spec:        common.StringOrNil(KeySpecRSA2048),
		Type:        common.StringOrNil(KeyTypeAsymmetric),
		Usage:       common.StringOrNil(KeyUsageSignVerify),
	}

	if !key.createPersisted(db) {
		return nil, fmt.Errorf("error creating/persisting %s key: %v", KeySpecRSA2048, *key.Errors[0].Message)
	}

	return key, nil
}

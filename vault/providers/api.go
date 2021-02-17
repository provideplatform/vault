package providers

import (
	"errors"
	"fmt"
)

// SealUnsealKeyProviderAWS AWS KMS unseal provider
const SealUnsealKeyProviderAWS = "aws_kms"

// SealUnsealKeyProviderAzureKeyVault Azure Key Vault unseal provider
const SealUnsealKeyProviderAzureKeyVault = "azure_key_vault"

// SealUnsealKeyProviderDocker docker unseal provider
const SealUnsealKeyProviderDocker = "docker"

// SealUnsealKeyProviderEnvironment environment variable unseal provider
const SealUnsealKeyProviderEnvironment = "environment"

// SealUnsealKeyProvider interface
type SealUnsealKeyProvider interface {
	Seed() (*string, error)
	ValidationHash() (*string, error)
}

// InitUnsealProvider initializes a seal/unseal provider
func InitSealUnsealProvider(provider string, params map[string]interface{}) (SealUnsealKeyProvider, error) {
	var sealUnseal SealUnsealKeyProvider

	switch provider {
	case SealUnsealKeyProviderAzureKeyVault:
		sealUnseal = InitAzureKeyVaultSealUnsealProvider(params)
		if sealUnseal == nil {
			return nil, errors.New("failed to initialize Azure seal/unseal provider")
		}
	case SealUnsealKeyProviderAWS:
		sealUnseal = InitAWSSealUnsealProvider(params)
		if sealUnseal == nil {
			return nil, errors.New("failed to initialize AWS KMS seal/unseal provider")
		}
	case SealUnsealKeyProviderDocker:
		sealUnseal = InitDockerSealUnsealProvider(params)
		if sealUnseal == nil {
			return nil, errors.New("failed to initialize docker seal/unseal provider")
		}
	case SealUnsealKeyProviderEnvironment:
		sealUnseal = InitEnvironmentSealUnsealProvider(params)
		if sealUnseal == nil {
			return nil, errors.New("failed to initialize environment seal/unseal provider")
		}
	default:
		return nil, fmt.Errorf("failed to initialize unrecognized seal/unseal provider: %s", provider)
	}

	return sealUnseal, nil
}

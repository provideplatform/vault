/*
 * Copyright 2017-2024 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

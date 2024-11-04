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
	"os"
)

// EnvironmentUnsealProvider implements the Unsealer interface
type EnvironmentSealUnsealProvider struct {
}

// InitEnvironmentSealUnsealProvider initializes and returns the default environment unseal provider
func InitEnvironmentSealUnsealProvider(params map[string]interface{}) *EnvironmentSealUnsealProvider {
	return &EnvironmentSealUnsealProvider{}
}

func (p *EnvironmentSealUnsealProvider) Seed() (*string, error) {
	seed := os.Getenv("SEAL_UNSEAL_KEY")
	if seed == "" {
		return nil, errors.New("failed to fetch or create seed using configured SEAL_UNSEAL_KEY environment variable")
	}

	return &seed, nil
}

func (p *EnvironmentSealUnsealProvider) ValidationHash() (*string, error) {
	hash := os.Getenv("SEAL_UNSEAL_VALIDATION_HASH")
	if hash == "" {
		return nil, errors.New("validation hash not provided by environent seal/unseal provider using configured SEAL_UNSEAL_VALIDATION_HASH environment variable")
	}

	return &hash, nil
}

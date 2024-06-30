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
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/provideplatform/vault/common"
)

// DockerSealUnsealProvider implements the Unsealer interface
type DockerSealUnsealProvider struct {
}

// InitDockerSealUnsealProvider initializes and returns the default environment unseal provider
func InitDockerSealUnsealProvider(params map[string]interface{}) *DockerSealUnsealProvider {
	return &DockerSealUnsealProvider{}
}

func (p *DockerSealUnsealProvider) Seed() (*string, error) {
	seed, err := getEnv("SEAL_UNSEAL_KEY_SECRET_PATH")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch or create seed using configured docker SEAL_UNSEAL_KEY_SECRET_PATH environment variable; %s", err.Error())
	}

	return seed, nil
}

func (p *DockerSealUnsealProvider) ValidationHash() (*string, error) {
	hash, err := getEnv("SEAL_UNSEAL_VALIDATION_HASH")
	if err != nil {
		return nil, fmt.Errorf("validation hash not provided by docker seal/unseal provider using configured SEAL_UNSEAL_VALIDATION_HASH environment variable; %s", err.Error())
	}

	return hash, nil
}

// getEnv gets environment data, including from docker secrets in-memory file system
func getEnv(s string) (*string, error) {
	// first check if it exists
	if s == "" {
		return nil, fmt.Errorf("environment variable %s not found", s)
	}

	var value string

	// then check if it's a docker secret
	if strings.HasPrefix(s, "/run/secrets") {
		data, err := ioutil.ReadFile(s)
		if err != nil {
			common.Log.Debugf("File reading error %s", err)
			return nil, err
		}
		value = string(data)
	}

	if value == "" {
		value = os.Getenv(s)
	}

	if value == "" {
		return nil, fmt.Errorf("environment variable %s not set", s)
	}

	return &value, nil
}

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

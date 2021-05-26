package providers

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go/api/c2"
)

// AWSSealUnsealProvider implements the Unsealer interface
type AWSSealUnsealProvider struct {
	region          string
	accessKeyID     string
	secretAccessKey string

	unsealKeySecretName string
}

// InitAWSSealUnsealProvider initializes and returns the AWS KMS Unseal provider
func InitAWSSealUnsealProvider(params map[string]interface{}) *AWSSealUnsealProvider {
	// credentials, credentialsOk := params["credentials"].(map[string]interface{})
	region, regionOk := params["region"].(string)
	if !regionOk {
		common.Log.Warning("failed to initialize AWS provider; credentials and region are required")
		return nil
	}

	// TODO-- determine how to best handle privileged execution setup

	return &AWSSealUnsealProvider{
		region: region,
	}
}

func (p *AWSSealUnsealProvider) targetCredentials() *provide.TargetCredentials {
	// TODO
	return nil
}

func (p *AWSSealUnsealProvider) Seed() (*string, error) {
	return nil, errors.New("AWS KMS provider not implemented")
}

func (p *AWSSealUnsealProvider) ValidationHash() (*string, error) {
	seed, err := p.Seed()
	if err != nil {
		return nil, fmt.Errorf("validation hash not calculated by seal/unseal provider using configured AWS KMS instance; %s", err.Error())
	}

	hash := crypto.SHA256.New()
	_, err = hash.Write([]byte(*seed))
	if err != nil {
		return nil, fmt.Errorf("validation hash not calculated by seal/unseal provider using configured AWS KMS instance; %s", err.Error())
	}

	return common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(hash.Sum(nil)))), nil
}

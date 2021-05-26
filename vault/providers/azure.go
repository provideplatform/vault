package providers

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	azurewrapper "github.com/kthomas/go-azure-wrapper"
	"github.com/provideapp/vault/common"
	vaultcrypto "github.com/provideapp/vault/crypto"
	provide "github.com/provideservices/provide-go/api/c2"
)

const defaultUnsealKeySecretName = "_unsealerkey"

// AzureSealUnsealProvider implements the Unsealer interface
type AzureSealUnsealProvider struct {
	region         string
	tenantID       string
	subscriptionID string
	clientID       string
	clientSecret   string
	vaultName      string

	unsealKeySecretName string
}

// InitAzureKeyVaultUnsealProvider initializes and returns the Microsoft Azure key vault Unseal provider
func InitAzureKeyVaultSealUnsealProvider(params map[string]interface{}) *AzureSealUnsealProvider {
	credentials, credentialsOk := params["credentials"].(map[string]interface{})
	if !credentialsOk && os.Getenv("SEAL_UNSEAL_VAULT_TENANT_ID") != "" && os.Getenv("SEAL_UNSEAL_VAULT_SUBSCRIPTION_ID") != "" {
		credentials = map[string]interface{}{
			"azure_tenant_id":       os.Getenv("SEAL_UNSEAL_VAULT_TENANT_ID"),
			"azure_subscription_id": os.Getenv("SEAL_UNSEAL_VAULT_SUBSCRIPTION_ID"),
		}
	}

	region, regionOk := params["region"].(string)
	if !regionOk && os.Getenv("SEAL_UNSEAL_VAULT_REGION") != "" {
		region = os.Getenv("SEAL_UNSEAL_VAULT_REGION")
		regionOk = true
	}

	if !credentialsOk || !regionOk {
		common.Log.Warning("failed to initialize Azure provider; credentials and region are required")
		return nil
	}

	tenantID, tenantIDOk := credentials["azure_tenant_id"].(string)
	subscriptionID, subscriptionIDOk := credentials["azure_subscription_id"].(string)
	clientID, clientIDOk := credentials["azure_client_id"].(string)
	clientSecret, _ := credentials["azure_client_secret"].(string)

	if !tenantIDOk || !subscriptionIDOk || !clientIDOk {
		common.Log.Warning("failed to initialize Azure provider; tenant_id, subscription_id, client_id are required")
		return nil
	}

	// if !clientSecretOk {
	// 	common.Log.Debugf("initializing Azure provider without client_secret; client will use managed identity authorization")
	// }

	unsealKeySecretName := defaultUnsealKeySecretName
	if os.Getenv("SEAL_UNSEAL_SECRET_NAME") != "" {
		unsealKeySecretName = os.Getenv("SEAL_UNSEAL_SECRET_NAME")
	}

	return &AzureSealUnsealProvider{
		region:              region,
		tenantID:            tenantID,
		subscriptionID:      subscriptionID,
		clientID:            clientID,
		clientSecret:        clientSecret,
		vaultName:           os.Getenv("SEAL_UNSEAL_VAULT_NAME"),
		unsealKeySecretName: unsealKeySecretName,
	}
}

func (p *AzureSealUnsealProvider) targetCredentials() *provide.TargetCredentials {
	return &provide.TargetCredentials{
		AzureTenantID:       common.StringOrNil(p.tenantID),
		AzureSubscriptionID: common.StringOrNil(p.subscriptionID),
		AzureClientID:       common.StringOrNil(p.clientID),
		AzureClientSecret:   common.StringOrNil(p.clientSecret),
	}
}

func (p *AzureSealUnsealProvider) Seed() (*string, error) {
	var bundle *keyvault.SecretBundle
	var err error

	bundle, err = p.fetchSecretBundle()
	if err != nil {
		common.Log.Debugf("failed to resolve vault seed from configured  Azure key vault; %s", err.Error())
		bundle, err = p.createSecretBundle()
		if err != nil {
			common.Log.Warningf("failed to create vault seed in configured Azure key vault; %s", err.Error())
			return nil, err
		}
	}

	return bundle.Value, nil
}

func (p *AzureSealUnsealProvider) ValidationHash() (*string, error) {
	seed, err := p.Seed()
	if err != nil {
		return nil, fmt.Errorf("validation hash not calculated by seal/unseal provider using configured Azure key vault; %s", err.Error())
	}

	hash := crypto.SHA256.New()
	_, err = hash.Write([]byte(*seed))
	if err != nil {
		return nil, fmt.Errorf("validation hash not calculated by seal/unseal provider using configured Azure key vault; %s", err.Error())
	}

	return common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(hash.Sum(nil)))), nil
}

func (p *AzureSealUnsealProvider) createSecretBundle() (*keyvault.SecretBundle, error) {
	client, err := azurewrapper.NewKeyVaultClient(p.targetCredentials())
	if err != nil {
		common.Log.Warning(fmt.Sprintf("failed to resolve Azure key vault client; %s", err.Error()))
		return nil, err
	}

	key, err := vaultcrypto.CreateHDWalletWithEntropy(vaultcrypto.DefaultHDWalletSeedEntropy)
	if err != nil {
		common.Log.Warning(fmt.Sprintf("failed to generate hd wallet seed; %s", err.Error()))
		return nil, err
	}

	seed := string(key.Seed)
	secret, err := client.SetSecret(context.TODO(), p.vaultBaseURL(), p.unsealKeySecretName, keyvault.SecretSetParameters{
		Value: &seed,
	})
	if err != nil {
		common.Log.Warning(fmt.Sprintf("failed to create Azure secret bundle; %s", err.Error()))
		return nil, err
	}

	return &secret, err
}

func (p *AzureSealUnsealProvider) fetchSecretBundle() (*keyvault.SecretBundle, error) {
	client, err := azurewrapper.NewKeyVaultClient(p.targetCredentials())
	if err != nil {
		common.Log.Warning(fmt.Sprintf("failed to resolve Azure key vault client; %s", err.Error()))
		return nil, err
	}

	secret, err := client.GetSecret(context.TODO(), p.vaultBaseURL(), p.unsealKeySecretName, "")
	if err != nil {
		common.Log.Warning(fmt.Sprintf("failed to fetch Azure secret bundle; %s", err.Error()))
		return nil, err
	}

	return &secret, err
}

func (p *AzureSealUnsealProvider) vaultBaseURL() string {
	return fmt.Sprintf("https://%s.vault.azure.net", p.vaultName)
}

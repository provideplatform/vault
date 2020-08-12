// +build unit

package test

import (
	"log"
	"testing"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	keyspgputil "github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
)

func init() {
	keyspgputil.RequirePGP()
}

var ethHDKeyDB = dbconf.DatabaseConnection()

func TestCreateEthHDWallet(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	wallet := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test key", "just some key :D")
	if wallet == nil {
		t.Errorf("failed to create eth HD wallet for vault: %s", vlt.ID)
		return
	}

	// it should have a seed
	if wallet.Seed == nil {
		t.Error("failed! seed not present for the hd wallet!")
		return
	}

	common.Log.Debugf("created eth HD wallet for vault: %s", vlt.ID)
}

func TestDeriveKeyFromEthHDWallet(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if walletKey == nil {
		t.Errorf("failed to create eth HD wallet for vault: %s", vlt.ID)
		return
	}

	idx := 1

	// test a sign with the key
	payload := []byte(common.RandomString(128))
	sig, err := walletKey.Sign(payload, &vault.SigningOptions{
		HDWallet: &vault.HDWalletOptions{
			Coin:  common.StringOrNil("ETH"),
			Index: &idx,
		},
	})
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}
	t.Log("about to verify with wallet key")
	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &vault.HDWalletOptions{
			Coin:  common.StringOrNil("ETH"),
			Index: &idx,
		},
	})
	if err != nil {
		t.Errorf("error validating signature: Error: %s", err.Error())
		return
	}
	t.Log("created and validated secp256k1 key")
}

func TestDeriveXKeysFromEthHDWallet(t *testing.T) {
	start := time.Now()
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}
	log.Printf("Vault creation took %s", time.Since(start))
	start = time.Now()
	walletKey := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if walletKey == nil {
		t.Errorf("failed to create eth HD wallet for vault: %s", vlt.ID)
		return
	}
	log.Printf("HD Wallet creation took %s", time.Since(start))

	var i int
	for i = 0; i < 5; i++ {
		// test a sign with the key
		payload := []byte(common.RandomString(128))
		start = time.Now()
		sig, err := walletKey.Sign(payload, &vault.SigningOptions{
			HDWallet: &vault.HDWalletOptions{
				Coin:  common.StringOrNil("ETH"),
				Index: &i,
			},
		})
		if err != nil {
			t.Errorf("error signing payload %s", err.Error())
		}

		log.Printf("Signing took %s", time.Since(start))
		start = time.Now()
		err = walletKey.Verify(payload, sig, &vault.SigningOptions{
			HDWallet: &vault.HDWalletOptions{
				Coin:  common.StringOrNil("ETH"),
				Index: &i,
			},
		})
		if err != nil {
			t.Errorf("error validating signature: Error: %s", err.Error())
			return
		}
		log.Printf("Verifying took %s", time.Since(start))
		t.Logf("created and validated secp256k1 key %d", i)
	}
}

func TestDeriveAutoKeyFromEthHDWallet(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if walletKey == nil {
		t.Errorf("failed to create eth HD wallet for vault: %s", vlt.ID)
		return
	}

	iteration := int(*walletKey.Iteration)

	// test a sign with the key
	payload := []byte(common.RandomString(128))
	sig, err := walletKey.Sign(payload, nil)
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}

	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &vault.HDWalletOptions{
			Coin:  common.StringOrNil("ETH"),
			Index: &iteration,
		},
	})
	if err != nil {
		t.Errorf("error validating signature: Error: %s", err.Error())
		return
	}

	t.Log("created and validated secp256k1 key")
}

func TestDeriveAutoKeyFromEthHDWallet_IncorrectVerifyIteration(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if walletKey == nil {
		t.Errorf("failed to create eth HD wallet for vault: %s", vlt.ID)
		return
	}

	iteration := int(*walletKey.Iteration)
	// test a sign with the key
	payload := []byte(common.RandomString(128))
	sig, err := walletKey.Sign(payload, nil)
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}

	// create an invalid iteration
	iteration++
	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &vault.HDWalletOptions{
			Coin:  common.StringOrNil("ETH"),
			Index: &iteration,
		},
	})
	if err == nil {
		t.Errorf("validated signature with incorrect iteration")
		return
	}

	t.Logf("got expected error validating sig with incorrect iteration %s", err.Error())
}

func TestDerivedKeyIteration(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	organizationId := vlt.OrganizationID

	walletKey := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if walletKey == nil {
		t.Errorf("failed to create eth HD wallet for vault: %s", vlt.ID)
		return
	}

	// now we'll retrieve the wallet key from the db
	dbKey := vault.GetVaultKey(walletKey.ID.String(), vlt.ID.String(), nil, organizationId, nil)
	if dbKey == nil {
		t.Errorf("failed to retrieve created key from DB, key ID %s", dbKey.ID)
		return
	}
	iteration := *dbKey.Iteration

	//sign something with the key
	payload := []byte(common.RandomString(128))
	sig, err := walletKey.Sign(payload, nil)
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}

	optionIteration := int(iteration)
	err = dbKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &vault.HDWalletOptions{
			Coin:  common.StringOrNil("ETH"),
			Index: &optionIteration,
		},
	})
	if err != nil {
		t.Errorf("error validating signature: Error: %s", err.Error())
		return
	}

	iteration++
	dbKey = vault.GetVaultKey(walletKey.ID.String(), vlt.ID.String(), nil, organizationId, nil)
	if dbKey == nil {
		t.Errorf("failed to retrieve created key from DB, key ID %s", dbKey.ID)
		return
	}

	if *dbKey.Iteration != iteration {
		t.Errorf("error in iteration. expected %d, got %d", iteration, *dbKey.Iteration)
		return
	}

	t.Logf("iterative signing OK for key id: %s, current iteration: %d", dbKey.ID, *dbKey.Iteration)
	return
}

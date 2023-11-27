//go:build unit
// +build unit

/*
 * Copyright 2017-2022 Provide Technologies Inc.
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

package test

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
	"github.com/provideplatform/vault/crypto"
	"github.com/provideplatform/vault/vault"
)

var ethHDKeyDB = dbconf.DatabaseConnection()

func init() {
	redisutil.RequireRedis()
}

func TestCreateEthHDWallet(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	wallet, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
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

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	idx := uint32(1)

	// test a sign with the key
	payload := []byte(common.RandomString(32))
	sig, err := walletKey.Sign(payload, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &idx,
		},
	})
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}
	t.Log("about to verify with wallet key")
	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &idx,
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
	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}
	log.Printf("HD Wallet creation took %s", time.Since(start))

	var i uint32
	for i = 0; i < 5; i++ {
		// test a sign with the key
		payload := []byte(common.RandomString(32))
		start = time.Now()
		sig, err := walletKey.Sign(payload, &vault.SigningOptions{
			HDWallet: &crypto.HDWallet{
				CoinAbbr: common.StringOrNil("ETH"),
				Index:    &i,
			},
		})
		if err != nil {
			t.Errorf("error signing payload %s", err.Error())
		}

		log.Printf("Signing took %s", time.Since(start))
		start = time.Now()
		err = walletKey.Verify(payload, sig, &vault.SigningOptions{
			HDWallet: &crypto.HDWallet{
				CoinAbbr: common.StringOrNil("ETH"),
				Index:    &i,
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

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	path, _ := accounts.ParseDerivationPath(*walletKey.IterativeDerivationPath)
	iteration := path[4]

	// test a sign with the key
	payload := []byte(common.RandomString(32))
	sig, err := walletKey.Sign(payload, nil)
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}

	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &iteration,
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

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	path, _ := accounts.ParseDerivationPath(*walletKey.IterativeDerivationPath)
	iteration := path[4]

	// test a sign with the key
	payload := []byte(common.RandomString(32))
	sig, err := walletKey.Sign(payload, nil)
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}

	// create an invalid iteration
	iteration++
	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &iteration,
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

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	// now we'll retrieve the wallet key from the db
	dbKey := vault.GetVaultKey(walletKey.ID.String(), vlt.ID.String(), nil, organizationId, nil)
	if dbKey == nil {
		t.Errorf("failed to retrieve created key from DB, key ID %s", dbKey.ID)
		return
	}

	path, _ := accounts.ParseDerivationPath(*dbKey.IterativeDerivationPath)
	iteration := path[len(path)-1]

	var keyIteration uint32

	for idx := 0; idx < 5; idx++ {
		keyIteration = iteration + uint32(idx)

		// sign something with the key
		t.Logf("loop %d, about to sign", idx)
		payload := []byte(common.RandomString(32))
		sig, err := walletKey.Sign(payload, nil)
		if err != nil {
			t.Errorf("error signing payload %s", err.Error())
			return
		}

		// then make sure the key in the db has been updated with the next iteration
		dbKey = vault.GetVaultKey(walletKey.ID.String(), vlt.ID.String(), nil, organizationId, nil)
		if dbKey == nil {
			t.Errorf("failed to retrieve created key from DB, key ID %s", dbKey.ID)
			return
		}

		path, _ := accounts.ParseDerivationPath(*dbKey.IterativeDerivationPath)
		iteration := path[4]

		if iteration != keyIteration+1 {
			t.Errorf("error in iteration. expected %d, got %d", keyIteration+1, iteration)
			return
		}

		t.Logf("validating for iteration %d", keyIteration)
		err = dbKey.Verify(payload, sig, &vault.SigningOptions{
			HDWallet: &crypto.HDWallet{
				CoinAbbr: common.StringOrNil("ETH"),
				Index:    &keyIteration,
			},
		})
		if err != nil {
			t.Errorf("error validating signature: Error: %s", err.Error())
			return
		}

	}

	t.Logf("iterative signing OK for key id: %s, current iteration: %d", dbKey.ID, keyIteration)
	return
}

func TestSignWithMaximumKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	idx := uint32(4294967295)

	// test a sign with the key
	payload := []byte(common.RandomString(32))
	sig, err := walletKey.Sign(payload, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &idx,
		},
	})
	if err != nil {
		t.Errorf("error signing payload %s", err.Error())
	}
	t.Log("about to verify with wallet key")
	err = walletKey.Verify(payload, sig, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &idx,
		},
	})
	if err != nil {
		t.Errorf("error validating signature: Error: %s", err.Error())
		return
	}
}

func TestSignWithArbitraryKeyIterationIndex(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	idx := uint32(10)
	// set the key to an invalid iterative derivation path
	// attempt to sign with the invalid key
	payload := []byte(common.RandomString(32))
	_, err = walletKey.Sign(payload, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("ETH"),
			Index:    &idx,
		},
	})
	if err != nil {
		t.Logf("got unexpected error signing with arbitrary coin_abbr and index %s", err.Error())
	}
}

func TestSignWithArbitraryKeyIterationPath(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	idx := uint32(10)
	pathstr := fmt.Sprintf("m/44'/60'/0'/0/%d", idx)
	// set the key to an invalid iterative derivation path
	// walletKey.DerivationPath = &pathstr

	// attempt to sign with the invalid key
	payload := []byte(common.RandomString(32))
	_, err = walletKey.Sign(payload, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			Path: &pathstr,
		},
	})
	if err != nil {
		t.Logf("got unexpected error signing with arbitrary derivation path %s", err.Error())
	}
}

func TestDeriveAutoKeyFromEthHDWallet_IncorrectCoin(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for eth hd wallet create unit test!")
		return
	}

	walletKey, err := vault.EthHDWalletFactory(ethHDKeyDB, &vlt.ID, "test wallet", "test hd wallet")
	if err != nil {
		t.Errorf("failed to create eth HD wallet for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	iteration := uint32(0)
	// test a sign with the key
	payload := []byte(common.RandomString(32))
	_, err = walletKey.Sign(payload, &vault.SigningOptions{
		HDWallet: &crypto.HDWallet{
			CoinAbbr: common.StringOrNil("BTC"),
			Index:    &iteration,
		},
	})
	if err == nil {
		t.Errorf("no error generating key for incorrect coin %s", err.Error())
	}

	t.Logf("got expected error generating signing key with invalid coin %s", err.Error())
}

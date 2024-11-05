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

package sealer

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/provideplatform/vault/common"
	vaultcrypto "github.com/provideplatform/vault/crypto"
	"github.com/provideplatform/vault/sealer/providers"
)

// nonce size for encrypt/decrypt
const NonceSizeSymmetric = 12 // FIXME-- remove this after completing audit/repackage of vault constants...

var (
	// seal/unseal provider implementation
	provider providers.SealUnsealKeyProvider

	// key for encrypt/decrypt of the master key for each vault instance
	sealUnsealKey []byte

	// cloaking key used to keep seal/unseal key encrypted in memory until required
	unsealerCloakingKey []byte
)

func init() {
	if os.Getenv("SEAL_UNSEAL_PROVIDER") != "" {
		provider, _ = providers.InitSealUnsealProvider(os.Getenv("SEAL_UNSEAL_PROVIDER"), map[string]interface{}{})
	} else {
		provider, _ = providers.InitSealUnsealProvider(providers.SealUnsealKeyProviderEnvironment, map[string]interface{}{})
	}

	if reflect.ValueOf(provider).IsNil() {
		common.Log.Panicf("failed to initialize vault seal/unseal provider")
	}
}

// SealUnsealRequestResponse provides the unseal information
type SealUnsealRequestResponse struct {
	SealUnsealKey  *string `json:"key,omitempty"`
	ValidationHash *string `json:"validation_hash,omitempty"`
}

// Attempt to automatically unseal the vault using the instance configuration
func AutoUnseal() error {
	seed, err := provider.Seed()
	if err != nil {
		return err
	}

	err = Unseal(seed)
	if err != nil {
		return err
	}

	common.Log.Debug("vault automatically unsealed")
	return nil
}

// Create a fresh seal/unseal key
func CreateUnsealerKey() (*SealUnsealRequestResponse, error) {
	// TODO-- if not environment provider, return err...

	key, err := vaultcrypto.CreateHDWalletWithEntropy(vaultcrypto.DefaultHDWalletSeedEntropy)
	if err != nil {
		return nil, err
	}

	seedKey := key.Seed
	sealUnsealKey := string(seedKey)

	// get the SHA256 hash of the generated unsealerkey
	validationHash := crypto.SHA256.New()
	_, err = validationHash.Write([]byte(seedKey))
	if err != nil {
		return nil, err
	}

	responseHash := common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(validationHash.Sum(nil))))

	response := SealUnsealRequestResponse{
		SealUnsealKey:  &sealUnsealKey,
		ValidationHash: responseHash,
	}

	return &response, nil
}

// Read the sealed or unsealed state of the vault
func IsSealed() bool {
	return len(sealUnsealKey) == 0
}

// Seal the vault instance to suspend vault operations until (i) a subsequent
// call to Unseal() is made or (ii) the instance configuration allows the
// vault to be automatically unsealed
func Seal(key string) error {
	if len(key) == 0 {
		return fmt.Errorf("error sealing vault; no seal/unseal key provided")
	}

	// get the SHA256 hash of the provided seal/unseal key
	incomingKeyHash := crypto.SHA256.New()
	_, err := incomingKeyHash.Write([]byte(key))
	if err != nil {
		return fmt.Errorf("error sealing vault; error hashing incoming key")
	}

	validationHash, err := provider.ValidationHash()
	if err != nil || len(validationHash) == 0 {
		return fmt.Errorf("error sealing vault; no seal/unseal validation hash present")
	}

	if strings.HasPrefix(string(validationHash), "0x") {
		validationHash = validationHash[2:]
	}

	validator, _ := hex.DecodeString(string(validationHash))

	// validate the SHA256 hash against the validation hash
	res := bytes.Compare(incomingKeyHash.Sum(nil), validator[:])
	if res != 0 {
		return fmt.Errorf("error sealing vault; seal/unseal key provided doesn't match validation hash")
	}
	common.Log.Debugf("sealing vault; valid vault unsealing key received")

	sealUnsealKey = nil
	unsealerCloakingKey = nil
	return nil
}

// Unseal the instance to enable vault operations until (i) a subsequent
// call to Seal() is made or (ii) the configured timeout is reached
func Unseal(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("error unsealing vault; no seal/unseal key provided")
	}

	// we can't unseal an unsealed vault
	if !IsSealed() {
		return nil
	}

	// get the SHA256 hash of the given key
	incomingKeyHash := crypto.SHA256.New()
	_, err := incomingKeyHash.Write([]byte(key))
	if err != nil {
		return fmt.Errorf("error unsealing vault; error hashing incoming key")
	}

	validationHash, err := provider.ValidationHash()
	if err != nil || len(validationHash) == 0 {
		return fmt.Errorf("error unsealing vault; no seal/unseal validation hash present")
	}

	if strings.HasPrefix(string(validationHash), "0x") {
		validationHash = validationHash[2:]
	}

	validator, _ := hex.DecodeString(string(validationHash))

	// validate the SHA256 hash against the validation hash
	res := bytes.Compare(incomingKeyHash.Sum(nil), validator[:])
	if res != 0 {
		return fmt.Errorf("error unsealing vault; seal/unseal key provided doesn't match validation hash")
	}
	common.Log.Debugf("valid vault unsealing key received")

	// set up a random cloaking key
	randomKey, err := vaultcrypto.CreateAES256GCMSeed()
	if err != nil {
		return fmt.Errorf("error unsealing vault; failed to generate cloaking key")
	}

	// set the cloaking key to this random key
	unsealerCloakingKey = randomKey

	// convert the cloaking key to an AES key to perform encryption
	cloakingKey := vaultcrypto.AES256GCM{
		PrivateKey: randomKey,
	}

	// get the original 32-byte entropy from the seed phrase - we will use this as the AES encryption key for the vaults
	sealUnsealKeySeed, err := vaultcrypto.GetEntropyFromMnemonic(string(key))
	if err != nil {
		return fmt.Errorf("error unsealing vault; recovering entropy from BIP39 passphrase failed")
	}

	if len(sealUnsealKeySeed) != common.UnsealerKeyRequiredBytes {
		return fmt.Errorf("error unsealing vault; 32-byte entropy required for AES encryption and is minimum required for vault security")
	}

	// encrypt the seal/unseal key with the cloaking key
	cloakedSealUnsealKey, err := cloakingKey.Encrypt(sealUnsealKeySeed, nil)
	if err != nil {
		return fmt.Errorf("error unsealing vault; failed to encrypt seal/unseal key with cloaking key")
	}

	// wipe the seal/unseal key seed in memory before garbage collection
	sealUnsealKeySeed, _ = common.RandomBytes(32) // FIXME-- linter should ignore this

	// set the vault seal/unseal key
	sealUnsealKey = cloakedSealUnsealKey
	return nil
}

func getSealUnsealKey() (*vaultcrypto.AES256GCM, error) {
	if len(unsealerCloakingKey) == 0 {
		return nil, fmt.Errorf("error unsealing vault; no cloaking key available")
	}

	// convert the cloaking key into an AES key
	cloakingKey := vaultcrypto.AES256GCM{
		PrivateKey: unsealerCloakingKey,
	}

	// decrypt the seal/unseal key with the cloaking key
	decryptedSealUnsealKey, err := cloakingKey.Decrypt(
		sealUnsealKey[NonceSizeSymmetric:],
		sealUnsealKey[0:NonceSizeSymmetric],
	)

	if err != nil {
		return nil, fmt.Errorf("error decrypting seal/unseal key %s", err.Error())
	}

	return &vaultcrypto.AES256GCM{
		PrivateKey: decryptedSealUnsealKey,
	}, nil
}

// encrypt the given key material using the seal/unseal key
func SealKey(unsealedKey []byte) ([]byte, error) {
	if len(sealUnsealKey) == 0 {
		return nil, fmt.Errorf("vault is sealed")
	}

	if len(unsealedKey) == 0 {
		return nil, fmt.Errorf("error sealing vault; no unsealed key")
	}

	sealUnsealKey, err := getSealUnsealKey()
	if err != nil {
		return nil, fmt.Errorf("error sealing vault: %s", err.Error())
	}

	sealedKey, err := sealUnsealKey.Encrypt(unsealedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error sealing vault: %s", err.Error())
	}

	return sealedKey, nil
}

// decrypt the given sealed key material using the seal/unseal key
func UnsealKey(sealedKey []byte) ([]byte, error) {
	if len(sealUnsealKey) == 0 {
		return nil, fmt.Errorf("vault is sealed")
	}

	if len(sealedKey) == 0 {
		return nil, fmt.Errorf("error unsealing vault; no sealed key")
	}

	sealUnsealKey, err := getSealUnsealKey()
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault %s", err.Error())
	}

	common.Log.Debugf("resolved %d-byte sealed key", len(sealedKey))

	unsealedKey, err := sealUnsealKey.Decrypt(sealedKey[NonceSizeSymmetric:], sealedKey[0:NonceSizeSymmetric])
	if err != nil {
		return nil, fmt.Errorf("error unsealing vault; %s", err.Error())
	}

	return unsealedKey, nil
}

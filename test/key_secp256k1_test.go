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
	"encoding/hex"
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
	"github.com/provideplatform/vault/vault"
)

var secpKeyDB = dbconf.DatabaseConnection()

func TestCreateKeySecp256k1(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key create unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	// it should have a private key
	privateKey := key.PrivateKey
	if privateKey == nil {
		t.Error("failed! private key was not set for the secp256k1 key!")
		return
	}
	// it should have a public key
	publicKey := key.PublicKey
	if publicKey == nil {
		t.Error("failed! public key was not set for the secp256k1 key!")
		return
	}
	// it should have a non-nil address enriched
	address := key.Address
	if address == nil {
		t.Error("failed! address was not set for the secp256k1 key!")
		return
	}

	common.Log.Debugf("created secp256k1 keypair for vault: %s with address %s", vlt.ID, *key.Address)
}

func TestSecp256k1Sign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key signing unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	common.Log.Debugf("signed message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1Verify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg, sig, nil)
	if err != nil {
		t.Errorf("failed to verify message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1NoVerifyInvalidMessage(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))
	msg_invalid := []byte(common.RandomString(32))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key.Verify(msg_invalid, sig, nil)
	if err == nil {
		t.Errorf("failed to not verify invalid message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify invalid message using secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSecp256k1NoVerifyInvalidSigningKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for secp256k1 key verify unit test!")
		return
	}

	key1, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key1", "test signing key")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair1 for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	key2, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key2", "test invalid verifying key")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair2 for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))

	sig, err := key1.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using secp256k1 keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	err = key2.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("verified message using incorrect secp256k1 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using invalid secp256k1 keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestCreateSECP256k1KeyWithNilDescription(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for derive symmetric key unit test!")
		return
	}

	_, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "secp256k1 public key", "")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}
}

func TestSign256k1NilPrivateKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for 256k1 key signing unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))
	key.PrivateKey = nil
	_, err = key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message using 256k1 keypair with nil private key for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with 256k1 key with no private key")
	}
}

func TestSign256k1NilSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for 256k1 key signing unit test!")
		return
	}

	key, err := vault.Secp256k1Factory(secpKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create secp256k1 keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(32))
	key.Spec = nil
	_, err = key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message using 256k1 keypair with nil spec for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with 256k1 key with nil spec")
	}
}

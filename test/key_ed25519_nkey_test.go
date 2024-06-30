//go:build unit
// +build unit

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

package test

import (
	"encoding/hex"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/common"
	"github.com/provideplatform/vault/vault"
)

func TestCreateKeyEd25519NKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519NKey key create unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	// it should have a private key
	seed := key.Seed
	if seed == nil {
		t.Error("failed! seed was not set for the Ed25519NKey key!")
		return
	}
	// it should have a public key
	publicKey := key.PublicKey
	if publicKey == nil {
		t.Error("failed! public key was not set for the Ed25519NKey key!")
		return
	}

	common.Log.Debugf("created Ed25519NKey keypair for vault: %s", vlt.ID)
}

func TestVerifyEd25519NKeyNilPublicKey(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("error signing message using ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	key.PublicKey = nil
	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("failed to verify message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using Ed25519NKey keypair with nil publickey for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestVerifyEd25519NKeyInvalidSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("error signing message using ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	invalidSpec := "non-existent key"
	key.Spec = &invalidSpec
	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("failed to verify message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using Ed25519NKey keypair with invalid spec for vault: %s; err: %s", vlt.ID, err.Error())
}

func TestVerifyEd25519NKeyNilSpec(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for ed25519 key signing unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("error signing message using ed25519 keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	key.Spec = nil
	err = key.Verify(msg, sig, nil)
	if err == nil {
		t.Errorf("failed to verify message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("correctly failed to verify message using Ed25519NKey keypair with nil spec for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestSignEd25519NKeyNilSeed(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519NKey key signing unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	key.Seed = nil
	_, err = key.Sign(msg, nil)
	if err == nil {
		t.Errorf("signed message using Ed25519NKey keypair with nil seed for vault: %s %s", vlt.ID, err.Error())
		return
	}
	if err != nil {
		common.Log.Debug("correctly failed to sign with ed25519 key with no seed")
	}
}

func TestEd25519NKeySign(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519NKey key signing unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	common.Log.Debugf("signed message using Ed25519NKey keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestEd25519NKeyVerify(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519NKey key verify unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	err = key.Verify(msg, sig, nil)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	common.Log.Debugf("verified message using Ed25519NKey keypair for vault: %s; sig: %s", vlt.ID, hex.EncodeToString(sig))
}

func TestEd25519NKeyVerifyFail(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("failed! no vault created for Ed25519NKey key verify unit test!")
		return
	}

	key, err := vault.Ed25519NKeyFactory(edKeyDB, &vlt.ID, "test key", "just some key :D")
	if err != nil {
		t.Errorf("failed to create Ed25519NKey keypair for vault: %s; Error: %s", vlt.ID, err.Error())
		return
	}

	msg := []byte(common.RandomString(10))
	invalidMsg := []byte(common.RandomString(10))

	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Errorf("failed to verify message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}

	if sig == nil {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s nil signature!", vlt.ID)
		return
	}

	if len(sig) != 64 {
		t.Errorf("failed to sign message using Ed25519NKey keypair for vault: %s received %d-byte signature: %s", vlt.ID, len(sig), sig)
		return
	}

	err = key.Verify(invalidMsg, sig, nil)
	if err == nil {
		t.Errorf("verified invalid message using Ed25519NKey keypair for vault: %s %s", vlt.ID, err.Error())
		return
	}
}

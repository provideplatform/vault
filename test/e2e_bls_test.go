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

// +build integration vault bls

package test

import (
	"encoding/hex"
	"testing"

	provide "github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/vault/common"
	cryptovault "github.com/provideplatform/vault/vault"
)

func TestCreateBLSKey(t *testing.T) {

	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	_, err = keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

}

func TestAPIVerifyBLSSignature(t *testing.T) {
	t.Parallel()
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, nil)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != true {
		t.Error("failed to verify signature for vault")
		return
	}
}

func TestAPIVerifyBLSSignature_ShouldFail(t *testing.T) {
	t.Parallel()
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	// generate a new random payload to ensure the signature fails
	payloadBytes, _ = common.RandomBytes(32)
	messageToSign = hex.EncodeToString(payloadBytes)

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, nil)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != false {
		t.Error("verified invalid BLS signature!")
		return
	}
}

func TestCreateAggregateSignature(t *testing.T) {
	t.Parallel()
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	// generate n keys
	const numKeys = 10

	// 	// set up a payload to sign
	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)

	// set up the array of hex-encoded signatures
	var signatures [numKeys]string
	var publicKeys [numKeys]string

	for looper := 0; looper < numKeys; looper++ {

		// generate a key
		key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
		if err != nil {
			t.Errorf("failed to create key; %s", err.Error())
			return
		}
		t.Logf("key generated. %s", key.ID)
		publicKeys[looper] = *key.PublicKey
		t.Logf("public key received: %s", *key.PublicKey)

		// sign the message
		sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
		if err != nil {
			t.Errorf("failed to sign message %s", err.Error())
			return
		}
		t.Logf("signature returned: %s", *sigresponse.Signature)
		signatures[looper] = *sigresponse.Signature
	}

	//ok, so let's try and call aggregate without doing anything
	aggresponse, err := provide.AggregateSignatures(token, map[string]interface{}{
		"signatures": signatures,
	})
	// get an aggregate without throwing an error (little dreams!)
	t.Logf("response: %+v", *aggresponse.AggregateSignature)
}

func TestVerifyAggregateSignature(t *testing.T) {
	t.Parallel()
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	// generate n keys
	const numKeys = 10

	// 	// set up a payload to sign
	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)

	// set up the array of hex-encoded signatures
	var signatures [numKeys]string
	var publicKeys [numKeys]string

	for looper := 0; looper < numKeys; looper++ {

		// generate a key
		key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
		if err != nil {
			t.Errorf("failed to create key; %s", err.Error())
			return
		}
		t.Logf("key generated. %s", key.ID)
		publicKeys[looper] = *key.PublicKey
		t.Logf("public key received: %s", *key.PublicKey)

		// sign the message
		sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
		if err != nil {
			t.Errorf("failed to sign message %s", err.Error())
			return
		}
		t.Logf("signature returned: %s", *sigresponse.Signature)
		signatures[looper] = *sigresponse.Signature
	}

	//ok, so let's try and call aggregate without doing anything
	aggresponse, err := provide.AggregateSignatures(token, map[string]interface{}{
		"signatures": signatures,
	})
	// get an aggregate without throwing an error (little dreams!)
	t.Logf("response: %+v", *aggresponse.AggregateSignature)

	//okay so now we have to validate it (otherwise it's just valid hex!)
	// to verify, we need to provide:
	// -message (n*32 bytes)
	// aggregate sig (hex)
	// public keys (array of hex)

	// set up the array of n hex messages
	var messages []string
	for looper := 0; looper < numKeys; looper++ {
		messages = append(messages, messageToSign)
	}

	verified, err := provide.VerifyAggregateSignatures(token, map[string]interface{}{
		"messages":    messages,
		"public_keys": publicKeys,
		"signature":   *aggresponse.AggregateSignature,
	})
	if err != nil {
		t.Errorf("error verifying bls signature. Error: %s", err.Error())
		return
	}

	if verified.Verified != true {
		t.Errorf("valid bls signature not verified")
		return
	}
	t.Logf("verified: %t", verified.Verified)

}

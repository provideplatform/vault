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

package crypto

import (
	"crypto/ed25519"

	"github.com/provideplatform/vault/common"
)

// CreateEd25519KeyPair creates an Ed25519 keypair
func CreateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during attempted Ed25519 keypair generation; %s", r)
		}
	}()

	return ed25519.GenerateKey(nil)
}

// FromSeed will recover an Ed25519 private key capable of signing and verifying signatures
func FromSeed(seed []byte) ed25519.PrivateKey {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during attempted Ed25519 private key initialization from the given seed; %s", r)
		}
	}()

	return ed25519.NewKeyFromSeed(seed)
}

// Ed25519Sign will attempt to sign a given input using the specified key
func Ed25519Sign(privateKey ed25519.PrivateKey, input []byte) []byte {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during attempted Ed25519 signing; %s", r)
		}
	}()

	return ed25519.Sign(privateKey, input)
}

// Ed25519Verify will attempt to verify a signed message
func Ed25519Verify(publicKey ed25519.PublicKey, input, sig []byte) error {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered during attempted Ed25519 signature verification; %s", r)
		}
	}()

	if !ed25519.Verify(publicKey, input, sig) {
		return ErrCannotVerifyPayload
	}

	return nil
}

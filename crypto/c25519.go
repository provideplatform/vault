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
	providecrypto "github.com/provideplatform/provide-go/crypto"
)

// C25519 is the internal struct for a C25519 keypair
type C25519 struct {
	PrivateKey []byte
	PublicKey  []byte
}

// CreateC25519KeyPair creates a C25519 keypair
func CreateC25519KeyPair() (*C25519, error) {
	publicKey, privateKey, err := providecrypto.C25519GenerateKeyPair()
	if err != nil {
		return nil, ErrCannotGenerateKey
	}

	c25519 := C25519{}
	c25519.PrivateKey = privateKey
	c25519.PublicKey = publicKey

	return &c25519, nil
}

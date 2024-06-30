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

package crypto

import (
	"bytes"
	"crypto/elliptic"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	providecrypto "github.com/provideplatform/provide-go/crypto"
)

// Secp256k1 is the internal struct for an asymmetric keypair
type Secp256k1 struct {
	PrivateKey     []byte
	PublicKey      []byte
	Address        *string
	DerivationPath *string //used for derived keys
}

// CreateSecp256k1KeyPair creates an secp256k1 keypair, including eth address
func CreateSecp256k1KeyPair() (*Secp256k1, error) {
	address, privkey, err := providecrypto.EVMGenerateKeyPair()
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	privateKey := math.PaddedBigBytes(privkey.D, privkey.Params().BitSize/8)
	publicKey := elliptic.Marshal(secp256k1.S256(), privkey.PublicKey.X, privkey.PublicKey.Y)

	secp256k1 := Secp256k1{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address, //this is added when the key is enriched
	}

	return &secp256k1, nil
}

// Sign uses SECP256k1 private key to sign the payload
// note that this mechanism is designed for Ethereum signing
func (k *Secp256k1) Sign(payload []byte) ([]byte, error) {
	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	secp256k1Key, err := ethcrypto.ToECDSA(k.PrivateKey)
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	sig, err := ethcrypto.Sign(payload, secp256k1Key)
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	return sig, nil
}

// Verify uses Secp256k1 public key to verify the payload's signature
func (k *Secp256k1) Verify(payload, sig []byte) error {
	// get the signature's public key
	sigPublicKey, err := ethcrypto.Ecrecover(payload, sig)
	if err != nil {
		return ErrCannotVerifyPayload
	}

	// get the public key from the vault key
	secp256k1PublicKey := k.PublicKey

	// check if the signature's public key corresponds to the vault public key
	verified := bytes.Equal(sigPublicKey, secp256k1PublicKey)

	if !verified {
		return ErrCannotVerifyPayload
	}

	return nil
}

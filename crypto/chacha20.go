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
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20"
)

// NonceSizeChaCha20 is the size of chacha20 nonce for encryption/decryption (in bytes).
const NonceSizeChaCha20 = 12

// ChaCha is the internal struct for a keypair using seed.
type ChaCha struct {
	Seed []byte
}

// ChaCha20 ...
type ChaCha20 interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Wipe()
}

// CreateChaChaSeed returns a suitable chacha20 seed
func CreateChaChaSeed() ([]byte, error) {
	_, privateKey, err := CreateEd25519KeyPair()
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	return privateKey.Seed(), nil
}

// Encrypt encrypts byte array using chacha20 key
// nonce is optional and a random nonce is generated if nil
// Never use more than 2^32 random nonces with a given key because of the risk of a repeat
func (k *ChaCha) Encrypt(plaintext []byte, nonce []byte) ([]byte, error) {

	// create a random nonce if nonce is nil
	if nonce == nil {
		nonce = make([]byte, NonceSizeChaCha20)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, ErrCannotGenerateNonce
		}
	}

	// nonce must be NonceSizeChaCha20 bytes in length
	if len(nonce) > NonceSizeChaCha20 {
		return nil, ErrNonceTooLong
	}

	if len(nonce) < NonceSizeChaCha20 {
		//pad the nonce
		padding := NonceSizeChaCha20 - len(nonce)%NonceSizeChaCha20
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		nonce = append(nonce, padtext...)
	}

	//NB: shared, unencrypted seed stored in only one memory location
	cipher, err := chacha20.NewUnauthenticatedCipher(k.Seed, nonce)
	if err != nil {
		return nil, ErrCannotEncrypt
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	ciphertext = append(nonce[:], ciphertext[:]...)

	return ciphertext, nil
}

// Decrypt decrypts byte array using chacha20 key and input nonce
func (k *ChaCha) Decrypt(ciphertext []byte, nonce []byte) ([]byte, error) {

	//NB: shared, unencrypted seed stored in only one memory location
	cipher, err := chacha20.NewUnauthenticatedCipher(k.Seed, nonce)
	if err != nil {
		return nil, ErrCannotDecrypt
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Wipe will randomize the contents of the seed key
func (k *ChaCha) Wipe() {
	io.ReadFull(rand.Reader, k.Seed)
	k.Seed = nil
}

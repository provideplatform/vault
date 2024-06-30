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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// NonceSizeAES256GCM is the size of the nonce used in AES256GCM operations
const NonceSizeAES256GCM = 12

// AES256GCMSeedSize is the size of the seed in bytes
const AES256GCMSeedSize = 32

// AES256GCM is the internal struct for a AES256GCM keypair using private key
type AES256GCM struct {
	PrivateKey []byte
}

// CreateAES256GCMSeed creates a seed for a new AES256GCM key
func CreateAES256GCMSeed() ([]byte, error) {
	_, privateKey, err := CreateEd25519KeyPair()
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	seed := privateKey.Seed()
	slicedSeed := seed[0:AES256GCMSeedSize]

	return slicedSeed, nil
}

// Encrypt encrypts byte array using AES256GCM key
// if nonce is nil, a random nonce is generated
// never use more than 2^32 random nonces with a given key because of the risk of a repeat.
func (k *AES256GCM) Encrypt(plaintext []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(k.PrivateKey)
	if err != nil {
		return nil, ErrCannotEncrypt
	}

	if nonce == nil {
		nonce = make([]byte, NonceSizeAES256GCM)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, ErrCannotEncrypt
		}
	}

	// nonce must be NonceSizeAES256GCM bytes in length
	if len(nonce) > NonceSizeAES256GCM {
		return nil, ErrNonceTooLong
	}

	if len(nonce) < NonceSizeAES256GCM {
		//pad the nonce
		padding := NonceSizeAES256GCM - len(nonce)%NonceSizeAES256GCM
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		nonce = append(nonce, padtext...)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCannotEncrypt
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	//append the nonce to the ciphertext
	ciphertext = append(nonce[:], ciphertext[:]...)

	return ciphertext, nil
}

// Decrypt decrypts byte array using AES256GCM key and input nonce
func (k *AES256GCM) Decrypt(ciphertext []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(k.PrivateKey)
	if err != nil {
		return nil, ErrCannotDecrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCannotDecrypt
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrCannotDecrypt
	}

	return plaintext, nil
}

// Wipe will randomize the contents of the seed key
func (k *AES256GCM) Wipe() {
	io.ReadFull(rand.Reader, k.PrivateKey)
	k.PrivateKey = nil
}

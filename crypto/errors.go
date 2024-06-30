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

import "errors"

var (

	// ErrCannotGeneratePublicKey is returned if the public key of a keypair cannot be generated
	ErrCannotGeneratePublicKey = errors.New("cannot generate public key")

	// ErrEncryptionPayloadTooLong is returned if the plaintext to be encrypted is too long for the algorithm
	ErrEncryptionPayloadTooLong = errors.New("encryption payload too long")

	// ErrUnsupportedRSASigningAlgorithm is returned if the signing algorithm is not supported
	ErrUnsupportedRSASigningAlgorithm = errors.New("unsupported RSA algorithm")

	// ErrNonceTooLong is the error returned if the nonce provided is longer than permitted
	ErrNonceTooLong = errors.New("nonce too long")

	// ErrCannotGenerateSeed is the error returned if seed generation fails.
	ErrCannotGenerateSeed = errors.New("cannot generate seed")

	// ErrCannotEncrypt is the error returned if the encryption fails.
	ErrCannotEncrypt = errors.New("failed to encrypt")

	// ErrCannotDecrypt is the error returned if the decryption fails.
	ErrCannotDecrypt = errors.New("failed to decrypt")

	// ErrCannotDecodeSeed is the error returned if the seed cannot be decoded.
	ErrCannotDecodeSeed = errors.New("cannot decode seed")

	// ErrCannotReadSeed is the error returned if the seed cannot be decoded.
	ErrCannotReadSeed = errors.New("cannot read seed")

	// ErrCannotSignPayload is the error returned if the payload cannot be signed
	ErrCannotSignPayload = errors.New("cannot sign payload")

	// ErrCannotVerifyPayload is the error returned if the payload cannot be verified
	ErrCannotVerifyPayload = errors.New("cannot verify payload")

	// ErrNilPrivateKey is the error returned when required private key is not present
	ErrNilPrivateKey = errors.New("nil private key")

	// ErrCannotUnmarshallSignature is the error returned when the signature cannot be unmarshalled
	ErrCannotUnmarshallSignature = errors.New("cannot unmarshall signature")

	// ErrCannotDecodeKey is the error returned when the key cannot be decoded
	ErrCannotDecodeKey = errors.New("cannot decode key")

	// ErrCannotGenerateKey is the error returned if key generation fails
	ErrCannotGenerateKey = errors.New("cannot generate key")

	// ErrCannotGenerateNonce is the error returned if a random nonce generation fails
	ErrCannotGenerateNonce = errors.New("cannot generate nonce")

	// ErrInvalidPrefixByte is the error returned if the prefix byte is invalid
	ErrInvalidPrefixByte = errors.New("invalid prefix byte")

	// ErrInvalidKey is the error returned if the key is invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrInvalidPublicKey is the error returned if the public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidSeedLen is the error returned if the seed length is invalid
	ErrInvalidSeedLen = errors.New("invalid seed length")

	// ErrInvalidSeed is the error returned if the seed is invalid
	ErrInvalidSeed = errors.New("invalid seed")

	// ErrInvalidEncoding is the error returned if the encoding is invalid
	ErrInvalidEncoding = errors.New("invalid encoded key")

	// ErrInvalidSignature is the error returned if the signature is invalid
	ErrInvalidSignature = errors.New("signature verification failed")

	// ErrCannotSign is the error returned if no private key is available to sign message
	ErrCannotSign = errors.New("can not sign, no private key available")

	// ErrPublicKeyOnly is the error returned if no seed or private key is available
	ErrPublicKeyOnly = errors.New("no seed or private key available")

	// ErrIncompatibleKey is the error returned if the key is incompatible
	ErrIncompatibleKey = errors.New("incompatible key")

	// ErrInvalidChecksum is the error returned if the checksum is invalid
	ErrInvalidChecksum = errors.New("nkeys: invalid checksum")
)

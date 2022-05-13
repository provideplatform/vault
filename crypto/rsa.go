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
	"crypto"
	"crypto/rand"
	rsa "crypto/rsa"
	"crypto/sha256"
	"encoding/json"

	"github.com/kthomas/go-pgputil"
	"github.com/provideplatform/vault/common"
	"golang.org/x/crypto/ssh"
)

// RSAKeyPair is the internal struct for an asymmetric keypair
type RSAKeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// NonceSizeRSA is the size of the optional RSA nonce for encryption/decryption (in bytes)
const NonceSizeRSA = 32

// PSSSignature is used for handling signatures using RSASSA-PSS
const PSSSignature = "PSS"

// PKCSSignature is used for handling RSA signatures using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
const PKCSSignature = "PKCS"

// SigningAlgorithmRSA stores the signing algorithm details for RSA signing/verifying
type SigningAlgorithmRSA struct {
	Name string
	Hash crypto.Hash
	Type string
}

// SigningMethodRSA stores the signing method details and options for RSA signing/verifying
type SigningMethodRSA struct {
	*SigningAlgorithmRSA
	Options *rsa.PSSOptions
}

var (
	signatureAlgoPS256 *SigningMethodRSA
	signatureAlgoPS384 *SigningMethodRSA
	signatureAlgoPS512 *SigningMethodRSA
	signatureAlgoRS256 *SigningMethodRSA
	signatureAlgoRS384 *SigningMethodRSA
	signatureAlgoRS512 *SigningMethodRSA
)

func init() {

	// PS256
	signatureAlgoPS256 = &SigningMethodRSA{
		&SigningAlgorithmRSA{
			Name: "PS256",
			Hash: crypto.SHA256,
			Type: PSSSignature,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		},
	}

	// PS384
	signatureAlgoPS384 = &SigningMethodRSA{
		&SigningAlgorithmRSA{
			Name: "PS384",
			Hash: crypto.SHA384,
			Type: PSSSignature,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA384,
		},
	}

	// PS512
	signatureAlgoPS512 = &SigningMethodRSA{
		&SigningAlgorithmRSA{
			Name: "PS512",
			Hash: crypto.SHA512,
			Type: PSSSignature,
		},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA512,
		},
	}

	// RS256
	signatureAlgoRS256 = &SigningMethodRSA{
		&SigningAlgorithmRSA{
			Name: "RS256",
			Hash: crypto.SHA256,
			Type: PKCSSignature,
		}, nil,
	}

	// RS384
	signatureAlgoRS384 = &SigningMethodRSA{
		&SigningAlgorithmRSA{
			Name: "RS384",
			Hash: crypto.SHA384,
			Type: PKCSSignature,
		}, nil,
	}

	// RS512
	signatureAlgoRS512 = &SigningMethodRSA{
		&SigningAlgorithmRSA{
			Name: "RS512",
			Hash: crypto.SHA512,
			Type: PKCSSignature,
		}, nil,
	}
}

// // RSA PrivateKey internal struct for reference
// type PrivateKey struct {
// 	PublicKey            // public part.
// 	D         *big.Int   // private exponent
// 	Primes    []*big.Int // prime factors of N, has >= 2 elements.

// 	// Precomputed contains precomputed values that speed up private
// 	// operations, if available.
// 	Precomputed PrecomputedValues
// }

// CreateRSAKeyPair creates an RSA keypair
func CreateRSAKeyPair(bitsize int) (*RSAKeyPair, error) {

	// generates a private key struct as shown above (type PrivateKey)
	privateKey, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil {
		return nil, ErrCannotGenerateKey
	}

	RSAKeyPair := RSAKeyPair{}

	// next we'll convert the private key to bytes for storing in the db etc
	privkey, err := json.Marshal(*privateKey)
	if err != nil {
		return nil, ErrCannotGenerateKey
	}
	RSAKeyPair.PrivateKey = privkey

	pubkey, err := json.Marshal(*&privateKey.PublicKey)
	if err != nil {
		return nil, ErrCannotGenerateKey
	}
	RSAKeyPair.PublicKey = pubkey

	return &RSAKeyPair, nil
}

func selectSignatureMethod(algo string) (*SigningMethodRSA, error) {

	switch algo {
	case "PS256":
		return signatureAlgoPS256, nil
	case "PS384":
		return signatureAlgoPS384, nil
	case "PS512":
		return signatureAlgoPS512, nil
	case "RS256":
		return signatureAlgoRS256, nil
	case "RS384":
		return signatureAlgoRS384, nil
	case "RS512":
		return signatureAlgoRS512, nil
	default:
		return nil, ErrUnsupportedRSASigningAlgorithm
	}

}

// Sign uses RSA private key to sign the payload (PS256 Implementation)
func (k *RSAKeyPair) Sign(payload []byte, algo string) ([]byte, error) {

	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	// get the private key struct from the privatekey bytes
	var rsaPrivateKey rsa.PrivateKey
	json.Unmarshal(k.PrivateKey, &rsaPrivateKey)

	// get the signature algorithm
	signingMethod, err := selectSignatureMethod(algo)
	if err != nil {
		return nil, err
	}

	// sign using the signature algorithm and private key
	signature, err := signingMethod.Sign(&rsaPrivateKey, payload)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Sign uses the specified signing algorithm to sign the payload
func (algo *SigningMethodRSA) Sign(rsaPrivateKey *rsa.PrivateKey, payload []byte) ([]byte, error) {

	// hash the payload using the specified algorithm hashing algorithm
	payloadHash := algo.Hash.New()
	payloadHash.Write(payload)

	var signature []byte
	var err error

	// sign the payload using the specified signature algorithm (PKCS or PSS)
	switch algo.Type {
	case PSSSignature:
		signature, err = rsa.SignPSS(rand.Reader, rsaPrivateKey, algo.Hash, payloadHash.Sum(nil), algo.Options)

	case PKCSSignature:
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, algo.Hash, payloadHash.Sum(nil))
	}

	if err != nil {
		return nil, err
	}

	// sign the payload
	return signature, nil
}

// Verify uses the RSA public key to verify a signature (PS256 implementation)
func (k *RSAKeyPair) Verify(payload, sig []byte, algo string) error {
	if k.PublicKey == nil {
		return ErrInvalidPublicKey
	}

	signingMethod, err := selectSignatureMethod(algo)
	if err != nil {
		return err
	}

	// get the rsa public key struct from the publickey bytes
	var rsaKey rsa.PrivateKey
	err = json.Unmarshal(k.PublicKey, &rsaKey.PublicKey)

	if err != nil {
		publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(k.PublicKey))
		if err != nil {
			return err
		}
		rsaKey.PublicKey = *publicKey
	}

	// verify the signature using the signature algorithm
	err = signingMethod.Verify(payload, sig, &rsaKey.PublicKey)
	if err != nil {
		return err
	}

	return nil

}

// Verify uses the specified signing algorithm to verify the payload
func (algo *SigningMethodRSA) Verify(payload, sig []byte, rsaPublicKey *rsa.PublicKey) error {

	// hash the payload using the signature algorithm hash type
	payloadHash := algo.Hash.New()
	payloadHash.Write(payload)

	var err error

	// verify the payload using the specified signature algorithm (PKCS or PSS)
	switch algo.Type {
	case PSSSignature:
		err = rsa.VerifyPSS(rsaPublicKey, algo.Hash, payloadHash.Sum(nil), sig, algo.Options)

	case PKCSSignature:
		err = rsa.VerifyPKCS1v15(rsaPublicKey, algo.Hash, payloadHash.Sum(nil), sig)
	}

	// if we have an error, it's an invalid signature
	if err != nil {
		return err
	}

	//no errors found, signature verified
	return nil
}

// Encrypt encrypts byte array using RSA public key
func (k *RSAKeyPair) Encrypt(plaintext []byte) ([]byte, error) {
	if k.PublicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	// get the rsa public key struct from the publickey bytes
	var rsaKey rsa.PrivateKey
	json.Unmarshal(k.PublicKey, &rsaKey.PublicKey)

	// check if we're trying to encrypt too large a payload
	// formula (for OAEP encryption) is keylen(bytes) -2 -2*hashsize(bytes)
	// we are using SHA256, so formula is keylen(bytes) - 66
	maxlen := rsaKey.PublicKey.Size() - 66
	if len(plaintext) > maxlen {
		return nil, ErrEncryptionPayloadTooLong
	}

	// encrypt using OAEP
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
	if err != nil {
		return nil, ErrCannotEncrypt
	}
	return ciphertext, nil
}

// Decrypt decrypts byte array using RSA and input nonce
func (k *RSAKeyPair) Decrypt(ciphertext []byte) ([]byte, error) {
	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	//get the private key struct from the privatekey bytes
	var rsaPrivateKey rsa.PrivateKey
	json.Unmarshal(k.PrivateKey, &rsaPrivateKey)

	// decrypt using OAEP
	plaintext, err := rsaPrivateKey.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, ErrCannotDecrypt
	}
	return plaintext, nil
}

// SSHFingerprint returns the SSH fingerprint for the given RSA public key
func SSHFingerprint(rsaPublicKeyPEM []byte) ([]byte, error) {
	publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM(rsaPublicKeyPEM)
	if err != nil {
		common.Log.Warningf("failed to decode RSA public key from PEM; %s", err.Error())
		return nil, err
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		common.Log.Warningf("failed to decode SSH public key for fingerprinting; %s", err.Error())
		return nil, err
	}

	return []byte(ssh.FingerprintLegacyMD5(sshPublicKey)), nil
}

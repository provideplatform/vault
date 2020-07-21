package crypto

import (
	"crypto"
	"crypto/rand"
	rsa "crypto/rsa"
	"crypto/sha256"
	"encoding/json"
)

// RSAKeyPair is the internal struct for an asymmetric keypair
type RSAKeyPair struct {
	PrivateKey *[]byte
	PublicKey  *[]byte
}

// NonceSizeRSA is the size of the optional RSA nonce for encryption/decryption (in bytes)
const NonceSizeRSA = 32

// type SigningMethodRSA struct {
// 	Name string
// 	Hash crypto.Hash
// }

// type SigningMethodRSAPSS struct {
// 	*SigningMethodRSA
// 	Options *rsa.PSSOptions
// 	// VerifyOptions is optional. If set overrides Options for rsa.VerifyPPS.
// 	// Used to accept tokens signed with rsa.PSSSaltLengthAuto, what doesn't follow
// 	// https://tools.ietf.org/html/rfc7518#section-3.5 but was used previously.
// 	// See https://github.com/dgrijalva/jwt-go/issues/285#issuecomment-437451244 for details.
// 	VerifyOptions *rsa.PSSOptions
// }

// var (
// 	SigningMethodPS256 *SigningMethodRSAPSS
// 	SigningMethodPS384 *SigningMethodRSAPSS
// 	SigningMethodPS512 *SigningMethodRSAPSS
// )

// // PrivateKey for information only
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
	RSAKeyPair.PrivateKey = &privkey

	pubkey, err := json.Marshal(*&privateKey.PublicKey)
	if err != nil {
		return nil, ErrCannotGenerateKey
	}
	RSAKeyPair.PublicKey = &pubkey

	return &RSAKeyPair, nil
}

// func init() {

// 	// PS256 testing
// 	SigningMethodPS256 = &SigningMethodRSAPSS{
// 		&SigningMethodRSA{
// 			Name: "PS256",
// 			Hash: crypto.SHA256,
// 		},
// 		&rsa.PSSOptions{
// 			SaltLength: rsa.PSSSaltLengthAuto,
// 			Hash:       crypto.SHA256,
// 		},
// 		&rsa.PSSOptions{
// 			SaltLength: rsa.PSSSaltLengthAuto,
// 			Hash:       crypto.SHA256,
// 		},
// 	}
// }

// // Sign uses RSA private key to sign the payload (PSS Implementation)
// // below should be a valid PS256 implementation
// // using the same code as the jwt package
// func (k *RSAKeyPair) Sign(payload []byte) ([]byte, error) {

// 	if k.PrivateKey == nil {
// 		return nil, ErrNilPrivateKey
// 	}

// 	//get the private key struct from the privatekey bytes
// 	var rsaPrivateKey rsa.PrivateKey
// 	json.Unmarshal(*k.PrivateKey, &rsaPrivateKey)

// 	signature, err := SigningMethodPS256.Sign(string(payload), &rsaPrivateKey)

// 	if err != nil {
// 		common.Log.Debugf("here - signing error %s", err.Error())
// 		return nil, ErrCannotSignPayload
// 	}

// 	return []byte(signature), nil
// }

// Sign uses RSA private key to sign the payload (PS256 Implementation)
func (k *RSAKeyPair) Sign(payload []byte) ([]byte, error) {

	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	// hash the payload with SHA256
	payloadHash := sha256.Sum256(payload)

	// payloadHash := sha512.Sum384(payload)
	// payloadHash := sha512.Sum512(payload)

	// set the pss options (primarily for hashing algorithm)
	opts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	//get the private key struct from the privatekey bytes
	var rsaPrivateKey rsa.PrivateKey
	json.Unmarshal(*k.PrivateKey, &rsaPrivateKey)

	signature, err := rsa.SignPSS(rand.Reader, &rsaPrivateKey, crypto.SHA256, payloadHash[:], &opts)
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	return signature, nil
}

// // Sign handles the actual RSA signing using the provided method (currently only PS256 available)
// // For this signing method, key must be an rsa.PrivateKey struct
// func (m *SigningMethodRSAPSS) Sign(signingString string, rsaPrivateKey *rsa.PrivateKey) (string, error) {

// 	hasher := m.Hash.New()
// 	hasher.Write([]byte(signingString))

// 	// Sign the string and return the encoded bytes
// 	signature, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, m.Hash, hasher.Sum(nil), m.Options)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(signature), nil
// }

// // Verify implements the Verify method from SigningMethod
// // For this verify method, key must be an rsa.PublicKey struct
// func (m *SigningMethodRSAPSS) Verify(signingString, sig []byte, rsaPublicKey *rsa.PublicKey) error {

// 	hasher := m.Hash.New()
// 	hasher.Write([]byte(signingString))

// 	return rsa.VerifyPSS(rsaPublicKey, m.Hash, hasher.Sum(nil), sig, m.Options)
// }

// // Verify uses the RSA public key to verify a signature (PS256 implementation)
// // using the same code as the jwt package
// func (k *RSAKeyPair) Verify(payload, sig []byte) error {
// 	if k.PublicKey == nil {
// 		return ErrInvalidPublicKey
// 	}

// 	// get the rsa public key struct from the publickey bytes
// 	var rsaKey rsa.PrivateKey
// 	json.Unmarshal(*k.PublicKey, &rsaKey.PublicKey)

// 	err := SigningMethodPS256.Verify(payload, sig, &rsaKey.PublicKey)
// 	if err != nil {
// 		return ErrCannotVerifyPayload
// 	}
// 	return nil
// }

// Verify uses the RSA public key to verify a signature (PS256 implementation)
func (k *RSAKeyPair) Verify(payload, sig []byte) error {
	if k.PublicKey == nil {
		return ErrInvalidPublicKey
	}

	// hash the payload with SHA256
	payloadHash := sha256.Sum256(payload)
	// payloadHash := sha512.Sum384(payload)
	// payloadHash := sha512.Sum512(payload)

	// get the rsa public key struct from the publickey bytes
	var rsaKey rsa.PrivateKey
	json.Unmarshal(*k.PublicKey, &rsaKey.PublicKey)

	// set the pss options (primarily for hashing algorithm)
	opts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	err := rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, payloadHash[:], sig, &opts)
	if err != nil {
		return ErrCannotVerifyPayload
	}
	return nil
}

// Encrypt encrypts byte array using RSA public key
func (k *RSAKeyPair) Encrypt(plaintext []byte) ([]byte, error) {
	if k.PublicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	// get the rsa public key struct from the publickey bytes
	var rsaKey rsa.PrivateKey
	json.Unmarshal(*k.PublicKey, &rsaKey.PublicKey)

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
	json.Unmarshal(*k.PrivateKey, &rsaPrivateKey)

	plaintext, err := rsaPrivateKey.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, ErrCannotDecrypt
	}
	return plaintext, nil
}

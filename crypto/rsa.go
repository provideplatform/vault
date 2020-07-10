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

// Sign uses RSA private key to sign the payload (PSS Implementation)
func (k *RSAKeyPair) Sign(payload []byte) ([]byte, error) {

	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	// hash the payload with SHA256
	payloadHash := sha256.Sum256(payload)

	//get the private key struct from the privatekey bytes
	var rsaPrivateKey rsa.PrivateKey
	json.Unmarshal(*k.PrivateKey, &rsaPrivateKey)

	signature, err := rsa.SignPSS(rand.Reader, &rsaPrivateKey, crypto.SHA256, payloadHash[:], nil)
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	return signature, nil
}

// Verify uses the RSA public key to verify a signature (PSS implementation)
func (k *RSAKeyPair) Verify(payload, sig []byte) error {
	if k.PublicKey == nil {
		return ErrInvalidPublicKey
	}

	// hash the payload with SHA256
	payloadHash := sha256.Sum256(payload)

	// get the rsa public key struct from the publickey bytes
	var rsaKey rsa.PrivateKey
	json.Unmarshal(*k.PublicKey, &rsaKey.PublicKey)

	err := rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, payloadHash[:], sig, nil)
	if err != nil {
		return ErrCannotVerifyPayload
	}
	return nil
}

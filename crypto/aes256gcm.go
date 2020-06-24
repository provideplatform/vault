package crypto

import (
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
	PrivateKey *[]byte
}

// CreateAES256GCMSeed creates a seed for a new AES256GCM key
func CreateAES256GCMSeed() ([]byte, error) {
	keypair, err := CreatePair(PrefixByteSeed)
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	seed, err := keypair.Seed()
	if err != nil {
		return nil, ErrCannotReadSeed
	}

	slicedSeed := seed[0:AES256GCMSeedSize]

	return slicedSeed, nil
}

//Encrypt encrypts byte array using AES256GCM key
func (k *AES256GCM) Encrypt(plaintext []byte) ([]byte, error) {
	//key := *k.PrivateKey

	block, err := aes.NewCipher(*k.PrivateKey)
	if err != nil {
		return nil, ErrCannotEncrypt
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, NonceSizeAES256GCM)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrCannotEncrypt
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

	block, err := aes.NewCipher(*k.PrivateKey)
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
	io.ReadFull(rand.Reader, *k.PrivateKey)
	k.PrivateKey = nil
}

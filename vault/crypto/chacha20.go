package vault

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20"
)

// NonceSizeChaCha20 is the size of chacha20 nonce for encryption/decryption (in bytes).
const NonceSizeChaCha20 = 12

var (
	//ErrCannotGenerateSeed is the error returned if chacha20 seed generation fails.
	ErrCannotGenerateSeed = errors.New("cannot generate seed")

	//ErrCannotEncrypt is the error returned if the chacha20 encryption fails.
	ErrCannotEncrypt = errors.New("failed to encrypt")

	//ErrCannotDecrypt is the error returned if the chacha20 decryption fails.
	ErrCannotDecrypt = errors.New("failed to decrypt")

	//ErrCannotDecodeSeed is the error returned if the chacha20 seed cannot be decoded.
	ErrCannotDecodeSeed = errors.New("cannot decode seed")
)

// ChaCha is the internal struct for a keypair using seed.
type ChaCha struct {
	seed []byte
}

// ChaCha20 ...
type ChaCha20 interface {
	create() ([]byte, error)
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Wipe()
}

// CreateChaChaSeed returns a suitable chacha20 seed
func CreateChaChaSeed() ([]byte, error) {
	keypair, err := CreatePair(PrefixByteSeed)
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	//NB: unencrypted seed stored in memory
	seed, err := keypair.Seed()
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	_, seed, err = DecodeSeed(seed)
	if err != nil {
		return nil, err
	}

	return seed, nil //no errors found in execution
}

//Encrypt encrypts byte array using chacha20 key
func (k *ChaCha) Encrypt(input []byte) ([]byte, error) {

	// create a random nonce
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat
	nonce := make([]byte, NonceSizeChaCha20)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrCannotEncrypt
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(k.seed, nonce)
	if err != nil {
		return nil, ErrCannotEncrypt
	}

	ciphertext := make([]byte, len(input))
	cipher.XORKeyStream(ciphertext, input)
	ciphertextWithNonce := append(nonce[:], ciphertext[:]...)

	return ciphertextWithNonce, nil
}

// Decrypt decrypts byte array using chacha20 key
func (k *ChaCha) Decrypt(input []byte) ([]byte, error) {

	//key := []byte(key.seed)

	nonce := input[0:NonceSizeChaCha20]
	ciphertext := input[NonceSizeChaCha20:]

	cipher, err := chacha20.NewUnauthenticatedCipher(k.seed, nonce)
	if err != nil {
		return nil, ErrCannotDecrypt
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Wipe will randomize the contents of the seed key
func (k *ChaCha) Wipe() {
	io.ReadFull(rand.Reader, k.seed)
	k.seed = nil
}

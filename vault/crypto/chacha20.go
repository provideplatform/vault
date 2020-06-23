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

	// ErrCannotUnmarshallKey is the error returned when the signature cannot be unmarshalled
	ErrCannotUnmarshallSignature = errors.New("cannot unmarshall signature")

	// ErrCannotDecodeKey is the error returned when the key cannot be decoded
	ErrCannotDecodeKey = errors.New("cannot decode key")
)

// ChaCha is the internal struct for a keypair using seed.
type ChaCha struct {
	Seed *[]byte
}

// ChaCha20 ...
type ChaCha20 interface {
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

	//NB: shared, unencrypted seed stored in only one memory location
	seed, err := keypair.Seed()
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	_, seed, err = DecodeSeed(seed)
	if err != nil {
		return nil, ErrCannotDecodeSeed
	}

	return seed, nil //no errors found in execution
}

//Encrypt encrypts byte array using chacha20 key
func (k *ChaCha) Encrypt(plaintext []byte) ([]byte, error) {

	// create a random nonce
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat
	nonce := make([]byte, NonceSizeChaCha20)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrCannotEncrypt
	}

	//NB: shared, unencrypted seed stored in only one memory location
	cipher, err := chacha20.NewUnauthenticatedCipher(*k.Seed, nonce)
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
	cipher, err := chacha20.NewUnauthenticatedCipher(*k.Seed, nonce)
	if err != nil {
		return nil, ErrCannotDecrypt
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Wipe will randomize the contents of the seed key
func (k *ChaCha) Wipe() {
	io.ReadFull(rand.Reader, *k.Seed)
	k.Seed = nil
}

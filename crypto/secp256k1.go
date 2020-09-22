package crypto

import (
	"bytes"
	"crypto/elliptic"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	providecrypto "github.com/provideservices/provide-go/crypto"
)

// Secp256k1 is the internal struct for an asymmetric keypair
type Secp256k1 struct {
	PrivateKey     *[]byte
	PublicKey      *[]byte
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

	secp256k1 := Secp256k1{}
	secp256k1.PrivateKey = &privateKey
	secp256k1.PublicKey = &publicKey
	secp256k1.Address = address //this is added when the key is enriched

	return &secp256k1, nil
}

// Sign uses SECP256k1 private key to sign the payload
// note that this mechanism is designed for Ethereum signing
func (k *Secp256k1) Sign(payload []byte) ([]byte, error) {
	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	secp256k1Key, err := ethcrypto.ToECDSA(*k.PrivateKey)
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	hash := ethcrypto.Keccak256Hash(payload)

	sig, err := ethcrypto.Sign(hash.Bytes(), secp256k1Key)
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	return sig, nil
}

// Verify uses Secp256k1 public key to verify the payload's signature
func (k *Secp256k1) Verify(payload, sig []byte) error {

	// get the keccak256 hash of the payload
	hash := ethcrypto.Keccak256Hash(payload)

	// get the signature's public key
	sigPublicKey, err := ethcrypto.Ecrecover(hash.Bytes(), sig)
	if err != nil {
		return ErrCannotVerifyPayload
	}

	// get the public key from the vault key
	secp256k1PublicKey := k.PublicKey

	// check if the signature's public key corresponds to the vault public key
	verified := bytes.Equal(sigPublicKey, *secp256k1PublicKey)

	if !verified {
		return ErrCannotVerifyPayload
	}

	return nil
}

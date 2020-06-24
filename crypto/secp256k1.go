package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/provideapp/vault/common"
	"github.com/provideservices/provide-go"
)

// Secp256k1 is the internal struct for an asymmetric keypair
type Secp256k1 struct {
	PrivateKey *[]byte
	PublicKey  *[]byte //TODO: change to []byte for internal consistency
	Address    *string
}

// CreateSecp256k1KeyPair creates an secp256k1 keypair, including eth address
func CreateSecp256k1KeyPair() (*Secp256k1, error) {
	address, privkey, err := provide.EVMGenerateKeyPair()
	if err != nil {
		return nil, ErrCannotGenerateSeed
	}

	privateKey := math.PaddedBigBytes(privkey.D, privkey.Params().BitSize/8)
	publicKey := elliptic.Marshal(secp256k1.S256(), privkey.PublicKey.X, privkey.PublicKey.Y)

	secp256k1 := Secp256k1{}
	secp256k1.PrivateKey = &privateKey
	secp256k1.PublicKey = &publicKey
	secp256k1.Address = address

	return &secp256k1, nil
}

// Sign uses SECP256k1 private key to sign the payload
func (k *Secp256k1) Sign(payload []byte) ([]byte, error) {
	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	secp256k1Key, err := ethcrypto.ToECDSA([]byte(*k.PrivateKey))
	if err != nil {
		return nil, ErrCannotSignPayload
	}
	r, s, err := ecdsa.Sign(rand.Reader, secp256k1Key, payload)
	if err != nil {
		return nil, ErrCannotSignPayload
	}
	sig, err := asn1.Marshal(common.ECDSASignature{R: r, S: s})
	if err != nil {
		return nil, ErrCannotSignPayload
	}

	return sig, nil
}

// Verify uses Secp256k1 public key to verify the payload's signature
func (k *Secp256k1) Verify(payload, sig []byte) error {
	signature := common.ECDSASignature{}
	_, err := asn1.Unmarshal(sig, &signature)
	if err != nil {
		return ErrCannotUnmarshallSignature
		//return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to unmarshal ASN1-encoded signature; %s", len(payload), k.ID, err.Error())
	}
	//common.Log.Debugf("unmarshaled ASN1 signature r, s (%s, %s) for key %s", signature.R, signature.S, k.ID)

	// pubkey, err := *k.PublicKey
	// if err != nil {
	// 	return ErrCannotDecodeKey
	// 	//return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to decode public key hex; %s", len(payload), k.ID, err.Error())
	// }
	secp256k1Key, err := ethcrypto.UnmarshalPubkey(*k.PublicKey)
	if err != nil {
		return ErrCannotVerifyPayload
		//return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to unmarshal public key; %s", len(payload), k.ID, err.Error())
	}
	if !ecdsa.Verify(secp256k1Key, payload, signature.R, signature.S) {
		return ErrCannotVerifyPayload
		//return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s", len(payload), k.ID)
	}
	return nil
}

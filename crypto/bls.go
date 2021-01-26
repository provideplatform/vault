package crypto

import (
	"encoding/json"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// BLS12381KeyPair is the internal struct for a BLS12-381 keypair
type BLS12381KeyPair struct {
	PrivateKey *[]byte
	PublicKey  *[]byte
}

// CreateBLS12381KeyPair creates an BLS12-381 keypair
func CreateBLS12381KeyPair() (*BLS12381KeyPair, error) {

	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	// create private and public BLS keys using BLS library
	var privateKey bls.SecretKey
	privateKey.SetByCSPRNG()
	publicKey := privateKey.GetPublicKey()

	// convert the private and public key structs to bytes for storing in the DB etc.
	BLSKeyPair := BLS12381KeyPair{}

	privkey, err := json.Marshal(privateKey)
	if err != nil {
		return nil, ErrCannotGenerateKey
	}
	BLSKeyPair.PrivateKey = &privkey

	pubkey, err := json.Marshal(publicKey)
	if err != nil {
		return nil, ErrCannotGenerateKey
	}
	BLSKeyPair.PublicKey = &pubkey

	return &BLSKeyPair, nil
}

// Sign uses BLS12381 private key to sign the payload
func (k *BLS12381KeyPair) Sign(payload []byte) ([]byte, error) {

	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	var blsPrivateKey bls.SecretKey
	json.Unmarshal(*k.PrivateKey, &blsPrivateKey)

	// sign the payload and serialize to []byte
	sig := blsPrivateKey.SignByte(payload).Serialize()

	return sig, nil
}

// Verify uses BLS12381 public key to verify the payload's signature
func (k *BLS12381KeyPair) Verify(payload []byte, sig []byte) error {

	if k.PublicKey == nil {
		return ErrInvalidPublicKey
	}

	// get the BLS public key struct from the publickey bytes
	var blsPublicKey bls.PublicKey
	json.Unmarshal(*k.PublicKey, &blsPublicKey)

	//unmarshal the signature to bls.Sign struct
	blsSignature := bls.Sign{}

	json.Unmarshal(sig, &blsSignature)

	// verify the signature using the BLS public key
	verified := blsSignature.VerifyByte(&blsPublicKey, payload)

	if !verified {
		return ErrCannotVerifyPayload
	}

	return nil
}

package crypto

import (
	"github.com/herumi/bls-eth-go-binary/bls"
)

// BLS12381 is the internal struct for a BLS12-381 keypair
type BLS12381 struct {
	PrivateKey *bls.SecretKey
	PublicKey  *bls.PublicKey
}

// CreateBLS12381KeyPair creates an BLS12-381 keypair
func CreateBLS12381KeyPair() (*BLS12381, error) {

	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	var privateKey bls.SecretKey
	privateKey.SetByCSPRNG()

	publicKey := privateKey.GetPublicKey()

	bls12381 := BLS12381{
		PrivateKey: &privateKey,
		PublicKey:  publicKey,
	}

	return &bls12381, nil
}

// Sign uses BLS12381 private key to sign the payload
func (k *BLS12381) Sign(payload []byte) *bls.Sign {

	privateKey := k.PrivateKey
	sig := privateKey.SignByte(payload)

	return sig
}

// Verify uses BLS12381 public key to verify the payload's signature
func (k *BLS12381) Verify(payload []byte, sig bls.Sign) error {

	publicKey := k.PublicKey
	verified := sig.VerifyByte(publicKey, payload)

	if !verified {
		return ErrCannotVerifyPayload
	}

	return nil
}

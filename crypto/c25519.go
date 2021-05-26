package crypto

import (
	providecrypto "github.com/provideservices/provide-go/crypto"
)

// C25519 is the internal struct for a C25519 keypair
type C25519 struct {
	PrivateKey []byte
	PublicKey  []byte
}

// CreateC25519KeyPair creates a C25519 keypair
func CreateC25519KeyPair() (*C25519, error) {
	publicKey, privateKey, err := providecrypto.C25519GenerateKeyPair()
	if err != nil {
		return nil, ErrCannotGenerateKey
	}

	c25519 := C25519{}
	c25519.PrivateKey = privateKey
	c25519.PublicKey = publicKey

	return &c25519, nil
}

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"

	ecies "github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/provideplatform/vault/common"
)

// NonceSizeECIES is the size of the nonce used in ECIES operations
const NonceSizeECIES = 12

// ECIESEncrypt encrypts plaintext using the given public key per ECIES
func ECIESEncrypt(publicKey, plaintext, nonce []byte) ([]byte, error) {
	ecdsaPublicKey := new(ecdsa.PublicKey)
	ecdsaPublicKey.Curve = secp256k1.S256()
	ecdsaPublicKey.X, ecdsaPublicKey.Y = elliptic.Unmarshal(ecdsaPublicKey.Curve, publicKey)

	if ecdsaPublicKey.X == nil {
		common.Log.Warningf("failed to encrypt with public key; point is not on curve")
		return nil, ErrCannotEncrypt
	}

	// Note that `s1`` and `s2`` contain shared information that is
	// not part of the resulting ciphertext. `s1`` is fed into key
	// derivation, `s2`` is fed into the MAC. If the shared information
	// parameters aren't being used, they should be nil.
	var s1 []byte
	var s2 []byte

	if len(nonce) > 0 {
		s1 = nonce
	} else {
		s1 = make([]byte, NonceSizeECIES)
		if _, err := io.ReadFull(rand.Reader, s1); err != nil {
			return nil, ErrCannotEncrypt
		}

		if len(s1) > NonceSizeECIES {
			return nil, ErrNonceTooLong
		}

		if len(s1) < NonceSizeECIES {
			// pad the nonce
			padding := NonceSizeECIES - len(s1)%NonceSizeECIES
			padtext := bytes.Repeat([]byte{byte(padding)}, padding)
			s1 = append(s1, padtext...)
		}
	}

	ciphertext, err := ecies.Encrypt(
		rand.Reader,
		ecies.ImportECDSAPublic(ecdsaPublicKey),
		plaintext,
		s1,
		s2,
	)
	if err != nil {
		common.Log.Warningf("failed to encrypt with public key; %s", err.Error())
		return nil, ErrCannotEncrypt
	}

	return append(nonce[:], ciphertext[:]...), nil
}

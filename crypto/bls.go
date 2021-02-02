package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// BLS12381KeyPair is the internal struct for a BLS12-381 keypair
type BLS12381KeyPair struct {
	PrivateKey *[]byte
	PublicKey  *[]byte
}

// CreateBLS12381KeyPair creates an BLS12-381 keypair
func CreateBLS12381KeyPair() (*BLS12381KeyPair, error) {

	// create private and public BLS keys using BLS library
	var privateKey bls.SecretKey
	privateKey.SetByCSPRNG()
	publicKey := privateKey.GetPublicKey()

	// convert the private and public key structs to bytes for storing in the DB etc.
	BLSKeyPair := BLS12381KeyPair{}

	privkey := privateKey.Serialize()
	BLSKeyPair.PrivateKey = &privkey

	pubkey := publicKey.Serialize()
	BLSKeyPair.PublicKey = &pubkey

	return &BLSKeyPair, nil
}

// Sign uses BLS12381 private key to sign the payload
func (k *BLS12381KeyPair) Sign(payload []byte) ([]byte, error) {

	if k.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}

	var blsPrivateKey bls.SecretKey
	blsPrivateKey.Deserialize(*k.PrivateKey)

	// sign the payload and serialize to []byte
	sig := blsPrivateKey.SignByte(payload).Serialize()

	return sig, nil
}

// Verify uses BLS12381 public key to verify the payload's signature
func (k *BLS12381KeyPair) Verify(payload []byte, sig []byte) error {

	if k.PublicKey == nil {
		return ErrInvalidPublicKey
	}

	// deserialize the BLS public key struct from the publickey bytes
	var blsPublicKey bls.PublicKey
	blsPublicKey.Deserialize(*k.PublicKey)

	// deserialize the BLS signature from the sig bytes
	blsSignature := bls.Sign{}
	blsSignature.Deserialize(sig)

	// verify the signature using the BLS public key
	verified := blsSignature.VerifyByte(&blsPublicKey, payload)

	if !verified {
		return ErrCannotVerifyPayload
	}

	return nil
}

// AggregateSigs aggregates n BLS sigs into 1 bls sig
func AggregateSigs(signatures []*string) (*string, error) {
	// convert string array from hex to bytes
	signum := len(signatures)

	var blsSigs []bls.Sign

	for looper := 0; looper < signum; looper++ {

		// first convert each element in the input array from hex to bytes
		sigbytes, err := hex.DecodeString(*signatures[looper])
		if err != nil {
			return nil, fmt.Errorf("error decoding sig %s from hex to bytes. Error: %s", *signatures[looper], err.Error())
		}

		// now deserialize the bytes back into a bls sig
		var blsSignature = &bls.Sign{}
		err = blsSignature.Deserialize(sigbytes)
		if err != nil {
			return nil, fmt.Errorf("error deserializing sig %+v into bls sig", sigbytes)
		}

		// add the bls sig to the array
		blsSigs = append(blsSigs, *blsSignature)
	}

	//aggregate the signatures into a single BLS signature
	aggregateSig := &bls.Sign{}
	aggregateSig.Aggregate(blsSigs[:])

	// now serialize the sig to bytes and hexify it
	sighex := hex.EncodeToString(aggregateSig.Serialize())

	//return hex signature
	return &sighex, nil
}

// AggregateVerify is a placeholder function for the verification of aggregated bls sigs
func AggregateVerify(signature *string, messages, publickeys []*string) (bool, error) {

	// convert the hex signature to bytes
	sigBytes, err := hex.DecodeString(*signature)
	if err != nil {
		return false, fmt.Errorf("error converting bls signature from hex. Error: %s", err.Error())
	}

	// deserialize the bytes back into a bls signature
	blsSig := &bls.Sign{}
	err = blsSig.Deserialize(sigBytes)
	if err != nil {
		return false, fmt.Errorf("error deserializing to bls signature. Error: %s", err.Error())
	}

	// now convert the array of hex public keys back into an array of bls public keys
	blsPubKey := &bls.PublicKey{}
	var blsPubKeys []bls.PublicKey

	numKeys := len(publickeys)

	for looper := 0; looper < numKeys; looper++ {
		// get rid of the leading 0x if it exists
		pubkeyhex := *publickeys[looper]
		pubkeyhex = strings.Replace(pubkeyhex, "0x", "", -1)

		keyBytes, err := hex.DecodeString(pubkeyhex)
		if err != nil {
			return false, fmt.Errorf("error decoding hex public key %s to bytes. Error: %s", *publickeys[looper], err.Error())
		}
		err = blsPubKey.Deserialize(keyBytes)
		if err != nil {
			return false, fmt.Errorf("error deserializing key bytes to bls public key. Error: %s", err.Error())
		}

		// append the decoded, deserialized key to the array of bls keys
		blsPubKeys = append(blsPubKeys, *blsPubKey)
	}

	// join the payloads together into a single byte array
	var aggregatePayload []byte
	for looper := 0; looper < numKeys; looper++ {
		// convert each message from hex to bytes
		msghex := *messages[looper]
		msghex = strings.Replace(msghex, "0x", "", -1)

		msgBytes, err := hex.DecodeString(msghex)
		if err != nil {
			return false, fmt.Errorf("error converting hex message %s to bytes. Error: %s", msghex, err.Error())
		}
		aggregatePayload = append(aggregatePayload, msgBytes...)
	}

	// verify the aggregated signature using the combined payload
	verified := blsSig.AggregateVerifyNoCheck(blsPubKeys[:], aggregatePayload)
	return verified, nil
}

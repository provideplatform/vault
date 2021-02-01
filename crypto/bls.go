package crypto

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/provideapp/vault/common"
)

// BLS12381KeyPair is the internal struct for a BLS12-381 keypair
type BLS12381KeyPair struct {
	PrivateKey *[]byte
	PublicKey  *[]byte
}

// CreateBLS12381KeyPair creates an BLS12-381 keypair
func CreateBLS12381KeyPair() (*BLS12381KeyPair, error) {

	// TODO bls.Init is not threadsafe!
	bls.Init(bls.BLS12_381)

	bls.SetETHmode(bls.EthModeDraft07)

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

	// let's detour from generating keys into some aggregate tests...
	// verified := AggregateTestDifferentMessages()
	// common.Log.Debugf("verification of aggregate signature is: %t", verified)

	// verified = AggregateTestSameMessage()
	// common.Log.Debugf("verification of aggregate signature is: %t", verified)

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

// AggregateTestDifferentMessages is a local implementation of the aggregate keys function
// in order to run through in debug mode, just to get a working example
func AggregateTestDifferentMessages() bool {

	// TODO bls.Init is not threadsafe!
	bls.Init(bls.BLS12_381)

	bls.SetETHmode(bls.EthModeDraft07)

	// numKeys is the number of keys/signatures we'll aggregate
	const numKeys = 3

	var blsPubKeys [numKeys]bls.PublicKey
	var blsPrivKeys [numKeys]*bls.SecretKey

	// create the keys
	for looper := 0; looper < numKeys; looper++ {
		var privateKey bls.SecretKey
		privateKey.SetByCSPRNG()
		publicKey := privateKey.GetPublicKey()

		// put the key into the relevant key array
		blsPubKeys[looper] = *publicKey
		blsPrivKeys[looper] = &privateKey
	}

	// the payloads to be signed all have to be different
	// i.e. the keys are all signing somthing different
	// otherwise the aggregate will fail
	// interesting, because you can't aggregate everybody signing the same thing
	// I assume that's an ETH 2.0 thing because all the keys are signing something different?
	// create a payload and use the keys to create an array of signatures
	var aggregatePayload []byte
	var payloads [numKeys][]byte

	// get numKeys payloads
	for looper := 0; looper < numKeys; looper++ {
		// generate a different payload for each key
		payloadBytes, _ := common.RandomBytes(32)
		payloads[looper] = payloadBytes
	}

	// join the payloads together into a single byte array
	for looper := 0; looper < numKeys; looper++ {
		aggregatePayload = append(aggregatePayload, payloads[looper]...)
	}

	// use the private keys array to create an array of signatures of each payload
	var blsSigs [numKeys]bls.Sign

	for looper := 0; looper < numKeys; looper++ {
		blsSig := &bls.Sign{}
		blsSig = blsPrivKeys[looper].SignByte(payloads[looper])
		blsSigs[looper] = *blsSig
	}

	//aggregate the signatures into a single BLS signature
	aggregateSig := &bls.Sign{}
	aggregateSig.Aggregate(blsSigs[:])

	// verify the aggregated signature using the combined payload
	verified := aggregateSig.AggregateVerify(blsPubKeys[:], aggregatePayload)
	return verified
}

// AggregateTestSameMessage is a local implementation of the aggregate keys function
// looking at doing a fast verify of the same signed message
// in order to run through in debug mode, just to get a working example
func AggregateTestSameMessage() bool {

	// TODO bls.Init is not threadsafe!
	bls.Init(bls.BLS12_381)

	bls.SetETHmode(bls.EthModeDraft07)

	// numKeys is the number of keys/signatures we'll aggregate
	const numKeys = 3

	var blsPubKeys [numKeys]bls.PublicKey
	var blsPrivKeys [numKeys]*bls.SecretKey

	// create the keys
	for looper := 0; looper < numKeys; looper++ {
		var privateKey bls.SecretKey
		privateKey.SetByCSPRNG()
		publicKey := privateKey.GetPublicKey()

		// put the key into the relevant key array
		blsPubKeys[looper] = *publicKey
		blsPrivKeys[looper] = &privateKey
	}

	// the payloads to be signed can be the same
	// if we do a verify with no check flag
	var aggregatePayload []byte
	var payloads [numKeys][]byte

	// we'll set up a single message payload for all keys to sign
	payloadBytes, _ := common.RandomBytes(32)

	// get numKeys payloads
	for looper := 0; looper < numKeys; looper++ {
		// put the same payload into the payloads array
		payloads[looper] = payloadBytes
	}

	// join the payloads together into a single byte array
	for looper := 0; looper < numKeys; looper++ {
		aggregatePayload = append(aggregatePayload, payloads[looper]...)
	}

	// use the private keys array to create an array of signatures of each payload
	var blsSigs [numKeys]bls.Sign

	for looper := 0; looper < numKeys; looper++ {
		blsSig := &bls.Sign{}
		blsSig = blsPrivKeys[looper].SignByte(payloads[looper])
		blsSigs[looper] = *blsSig
	}

	//aggregate the signatures into a single BLS signature
	aggregateSig := &bls.Sign{}
	aggregateSig.Aggregate(blsSigs[:])

	// verify the aggregated signature using the combined payload
	verified := aggregateSig.AggregateVerifyNoCheck(blsPubKeys[:], aggregatePayload)
	return verified
}

// AggregateSigs is a placeholder function for the aggregation of BLS sigs
func AggregateSigs(signatures []*string) (*string, error) {
	// convert string array from hex to bytes
	// create an bls.Sign object
	// run the aggregate operation on the signatures
	// serialize the aggregate sig
	// convert it to hex
	// and return
	return nil, nil
}

// AggregateVerify is a placeholder function for the verification of aggregated bls sigs
func AggregateVerify(signature *string, messages, publickeys []*string) bool {
	// convert the signature back into a BLS signature
	// convert the publickeys into an array of n bls.PublicKeys
	// convert the payload into a []byte, ensuring the size is 32 *n
	// run the aggregateverifynocheck on the pub keys and messages
	// return true if it passes, or false if it fails
	return false
}

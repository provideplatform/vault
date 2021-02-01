// +build integration vault bls

package test

import (
	"encoding/hex"
	"testing"

	"github.com/provideapp/vault/common"
	cryptovault "github.com/provideapp/vault/vault"
	provide "github.com/provideservices/provide-go/api/vault"
)

func TestCreateBLSKey(t *testing.T) {

	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	_, err = keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

}

func TestAPIVerifyBLSSignature(t *testing.T) {
	t.Parallel()
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, nil)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != true {
		t.Error("failed to verify signature for vault")
		return
	}
}

func TestAPIVerifyBLSSignature_ShouldFail(t *testing.T) {
	t.Parallel()
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	// generate a new random payload to ensure the signature fails
	payloadBytes, _ = common.RandomBytes(32)
	messageToSign = hex.EncodeToString(payloadBytes)

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, nil)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != false {
		t.Error("verified invalid BLS signature!")
		return
	}
}

// func TestAPIVerifyAggregateBLSSignature(t *testing.T) {
// 	t.Parallel()
// 	token, err := userTokenFactory()
// 	if err != nil {
// 		t.Errorf("failed to create token; %s", err.Error())
// 		return
// 	}

// 	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
// 	if err != nil {
// 		t.Errorf("failed to create vault; %s", err.Error())
// 		return
// 	}

// 	var publickeys [3]bls.PublicKey
// 	blsPublicKey := &bls.PublicKey{}

// 	key1, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
// 	if err != nil {
// 		t.Errorf("failed to create key; %s", err.Error())
// 		return
// 	}

// 	// get the hex public key from the response
// 	pubkey := *key1.PublicKey
// 	t.Logf("public key: %s", pubkey)
// 	pubkey = strings.Replace(pubkey, "0x", "", -1)
// 	// convert it to bytes
// 	publickeybytes, err := hex.DecodeString(pubkey)
// 	if err != nil {
// 		t.Logf("error decoding public key 1 hex. Error: %s", err.Error())
// 	}
// 	t.Logf("public key bytes: %+v", publickeybytes)
// 	t.Logf("public key length: %d", len(publickeybytes))
// 	// deserialize it back into a bls public key
// 	err = blsPublicKey.Deserialize(publickeybytes)
// 	if err != nil {
// 		t.Errorf("error deserializing BLS public key. Error: %s", err.Error())
// 		return
// 	}
// 	publickeys[0] = *blsPublicKey

// 	key2, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
// 	if err != nil {
// 		t.Errorf("failed to create key; %s", err.Error())
// 		return
// 	}
// 	// get the hex public key from the response
// 	pubkey = *key2.PublicKey
// 	pubkey = strings.Replace(pubkey, "0x", "", -1)
// 	// convert it to bytes
// 	publickeybytes, err = hex.DecodeString(pubkey)
// 	if err != nil {
// 		t.Logf("error decoding public key 2 hex. Error: %s", err.Error())
// 	}
// 	// deserialize it back into a bls public key
// 	err = blsPublicKey.Deserialize(publickeybytes)
// 	if err != nil {
// 		t.Logf("error deserializing BLS public key 2. Error: %s", err.Error())
// 	}
// 	publickeys[1] = *blsPublicKey

// 	key3, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
// 	if err != nil {
// 		t.Errorf("failed to create key; %s", err.Error())
// 		return
// 	}
// 	// get the hex public key from the response
// 	pubkey = *key3.PublicKey
// 	pubkey = strings.Replace(pubkey, "0x", "", -1)
// 	// convert it to bytes
// 	publickeybytes, err = hex.DecodeString(pubkey)
// 	if err != nil {
// 		t.Logf("error decoding public key 3 hex. Error: %s", err.Error())
// 	}
// 	// deserialize it back into a bls public key
// 	err = blsPublicKey.Deserialize(publickeybytes)
// 	if err != nil {
// 		t.Logf("error deserializing BLS public key 3. Error: %s", err.Error())
// 	}
// 	publickeys[2] = *blsPublicKey

// 	// set up a payload to sign
// 	payloadBytes, _ := common.RandomBytes(32)
// 	messageToSign := hex.EncodeToString(payloadBytes)

// 	// create an array of signatures
// 	var signatures []bls.Sign
// 	blsSignature := &bls.Sign{}

// 	sigresponse1, err := provide.SignMessage(*token, vault.ID.String(), key1.ID.String(), messageToSign, nil)
// 	if err != nil {
// 		t.Errorf("failed to sign message %s", err.Error())
// 		return
// 	}
// 	// get the hex signature from the response
// 	signature := *sigresponse1.Signature
// 	signature = strings.Replace(signature, "0x", "", -1)
// 	// convert it to bytes
// 	signaturebytes, err := hex.DecodeString(signature)
// 	if err != nil {
// 		t.Logf("error decoding signature 1 hex. Error: %s", err.Error())
// 	}
// 	// deserialize it back into a bls signature
// 	err = blsSignature.Deserialize(signaturebytes)
// 	if err != nil {
// 		t.Logf("error deserializing BLS signature 1. Error: %s", err.Error())
// 	}
// 	signatures[0] = *blsSignature

// 	sigresponse2, err := provide.SignMessage(*token, vault.ID.String(), key2.ID.String(), messageToSign, nil)
// 	if err != nil {
// 		t.Errorf("failed to sign message %s", err.Error())
// 		return
// 	}
// 	// get the hex signature from the response
// 	signature = *sigresponse2.Signature
// 	signature = strings.Replace(signature, "0x", "", -1)
// 	// convert it to bytes
// 	signaturebytes, err = hex.DecodeString(signature)
// 	if err != nil {
// 		t.Logf("error decoding signature 2 hex. Error: %s", err.Error())
// 	}
// 	// deserialize it back into a bls signature
// 	err = blsSignature.Deserialize(signaturebytes)
// 	if err != nil {
// 		t.Logf("error deserializing BLS signature 2. Error: %s", err.Error())
// 	}
// 	signatures[1] = *blsSignature

// 	sigresponse3, err := provide.SignMessage(*token, vault.ID.String(), key3.ID.String(), messageToSign, nil)
// 	if err != nil {
// 		t.Errorf("failed to sign message %s", err.Error())
// 		return
// 	}
// 	// get the hex signature from the response
// 	signature = *sigresponse3.Signature
// 	signature = strings.Replace(signature, "0x", "", -1)
// 	// convert it to bytes
// 	signaturebytes, err = hex.DecodeString(signature)
// 	if err != nil {
// 		t.Logf("error decoding signature hex. Error: %s", err.Error())
// 	}
// 	// deserialize it back into a bls signature
// 	err = blsSignature.Deserialize(signaturebytes)
// 	if err != nil {
// 		t.Logf("error deserializing BLS signature 3. Error: %s", err.Error())
// 	}
// 	signatures[2] = *blsSignature

// 	// now let's aggregate the signatures
// 	blsAggregateSignature := &bls.Sign{}
// 	blsAggregateSignature.Aggregate(signatures)

// 	// and attempt to verify them
// 	verified := blsAggregateSignature.FastAggregateVerify(publickeys[:], payloadBytes)

// 	t.Logf("verified is: %t", verified)

// }

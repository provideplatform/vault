// +build integration vault bls

package test

import (
	"encoding/hex"
	"testing"

	"github.com/provideapp/vault/common"
	cryptovault "github.com/provideapp/vault/vault"
	provide "github.com/provideservices/provide-go/api/vault"
)

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
// 	blsPublicKey := bls.PublicKey{}

// 	key1, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
// 	if err != nil {
// 		t.Errorf("failed to create key; %s", err.Error())
// 		return
// 	}
// 	pubkey := *key1.PublicKey
// 	t.Logf("pubkey: %+v", pubkey)
// 	t.Logf("public key 1 (hex) is: %s", pubkey)
// 	pubkey = strings.Replace(pubkey, "0x", "", -1)
// 	t.Logf("public key 1 (hex) (replaced) is: %s", pubkey)
// 	publickeybytes, err := hex.DecodeString(pubkey)
// 	if err != nil {
// 		t.Logf("error decoding public key hex. Error: %s", err.Error())
// 	}
// 	t.Logf("public key bytes is: %+v", publickeybytes)
// 	err = blsPublicKey.Deserialize(publickeybytes)
// 	if err != nil {
// 		t.Logf("error deserializing BLS public key. Error: %s", err.Error())
// 	}
// 	t.Logf("assigning first public key to array")
// 	publickeys[0] = blsPublicKey
// 	t.Logf("assigned")

// 	key2, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
// 	if err != nil {
// 		t.Errorf("failed to create key; %s", err.Error())
// 		return
// 	}
// 	pubkey = *key2.PublicKey
// 	strings.Replace(pubkey, "0x", "", -1)
// 	publickeybytes, err = hex.DecodeString(pubkey)
// 	if err != nil {
// 		t.Logf("error decoding public key hex. Error: %s", err.Error())
// 	}
// 	err = blsPublicKey.Deserialize(publickeybytes)
// 	if err != nil {
// 		t.Logf("error deserializing public key. Error: %s", err.Error())
// 	}
// 	publickeys[1] = blsPublicKey

// 	key3, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecBLS12381, "namey name", "cute description")
// 	if err != nil {
// 		t.Errorf("failed to create key; %s", err.Error())
// 		return
// 	}
// 	pubkey = *key3.PublicKey
// 	strings.Replace(pubkey, "0x", "", -1)
// 	publickeybytes, err = hex.DecodeString(pubkey)
// 	if err != nil {
// 		t.Logf("error decoding public key hex. Error: %s", err.Error())
// 	}
// 	err = blsPublicKey.Deserialize(publickeybytes)
// 	publickeys[2] = blsPublicKey

// 	payloadBytes, _ := common.RandomBytes(32)
// 	messageToSign := hex.EncodeToString(payloadBytes)

// 	var signatures []bls.Sign
// 	blsSignature := bls.Sign{}

// 	sigresponse1, err := provide.SignMessage(*token, vault.ID.String(), key1.ID.String(), messageToSign, nil)
// 	if err != nil {
// 		t.Errorf("failed to sign message %s", err.Error())
// 		return
// 	}
// 	strings.Replace(*sigresponse1.Signature, "0x", "", -1)
// 	signaturebytes, err := hex.DecodeString(*sigresponse1.Signature)
// 	if err != nil {
// 		t.Logf("error decoding signature hex. Error: %s", err.Error())
// 	}
// 	json.Unmarshal(signaturebytes, &blsSignature)
// 	signatures[0] = blsSignature

// 	sigresponse2, err := provide.SignMessage(*token, vault.ID.String(), key2.ID.String(), messageToSign, nil)
// 	if err != nil {
// 		t.Errorf("failed to sign message %s", err.Error())
// 		return
// 	}
// 	strings.Replace(*sigresponse2.Signature, "0x", "", -1)
// 	signaturebytes, err = hex.DecodeString(*sigresponse2.Signature)
// 	if err != nil {
// 		t.Logf("error decoding signature hex. Error: %s", err.Error())
// 	}
// 	json.Unmarshal(signaturebytes, &blsSignature)
// 	signatures[1] = blsSignature

// 	sigresponse3, err := provide.SignMessage(*token, vault.ID.String(), key3.ID.String(), messageToSign, nil)
// 	if err != nil {
// 		t.Errorf("failed to sign message %s", err.Error())
// 		return
// 	}
// 	strings.Replace(*sigresponse3.Signature, "0x", "", -1)
// 	signaturebytes, err = hex.DecodeString(*sigresponse3.Signature)
// 	if err != nil {
// 		t.Logf("error decoding signature hex. Error: %s", err.Error())
// 	}
// 	json.Unmarshal(signaturebytes, &blsSignature)
// 	signatures[2] = blsSignature

// 	// now let's aggregate the signatures
// 	blsAggregateSignature := bls.Sign{}
// 	blsAggregateSignature.Aggregate(signatures)

// 	// and attempt to verify them
// 	verified := blsAggregateSignature.FastAggregateVerify(publickeys[:], payloadBytes)

// 	t.Logf("verified is: %t", verified)

// 	// verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key1.ID.String(), messageToSign, *sigresponse.Signature, nil)
// 	// if err != nil {
// 	// 	t.Errorf("failed to verify signature for vault: %s", err.Error())
// 	// 	return
// 	// }

// 	// if verifyresponse.Verified != true {
// 	// 	t.Error("failed to verify signature for vault")
// 	// 	return
// 	// }
// }

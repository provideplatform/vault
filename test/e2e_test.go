// +build integration

package test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	cryptovault "github.com/provideapp/vault/vault"
	ident "github.com/provideservices/provide-go/api/ident"
	provide "github.com/provideservices/provide-go/api/vault"
)

func keyFactoryEphemeral(token, vaultID, keyType, keyUsage, keySpec, keyName, keyDescription string) (*provide.Key, error) {
	resp, err := provide.CreateKey(token, vaultID, map[string]interface{}{
		"type":        keyType,
		"usage":       keyUsage,
		"spec":        keySpec,
		"name":        keyName,
		"description": keyDescription,
		"ephemeral":   true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create key error: %s", err.Error())
	}

	key := &provide.Key{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall key data: %s", err.Error())
	}
	json.Unmarshal(respRaw, &key)
	return key, nil
}

func keyFactory(token, vaultID, keyType, keyUsage, keySpec, keyName, keyDescription string) (*provide.Key, error) {
	resp, err := provide.CreateKey(token, vaultID, map[string]interface{}{
		"type":        keyType,
		"usage":       keyUsage,
		"spec":        keySpec,
		"name":        keyName,
		"description": keyDescription,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create key error: %s", err.Error())
	}

	key := &provide.Key{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall key data: %s", err.Error())
	}
	json.Unmarshal(respRaw, &key)
	return key, nil
}

func vaultFactory(token, name, desc string) (*provide.Vault, error) {
	resp, err := provide.CreateVault(token, map[string]interface{}{
		"name":        name,
		"description": desc,
	})
	if err != nil {
		return nil, err
	}
	vlt := &provide.Vault{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(respRaw, &vlt)
	return vlt, nil
}

func userFactory(email, password string) (*uuid.UUID, error) {
	resp, err := ident.CreateUser("", map[string]interface{}{
		"first_name": "A",
		"last_name":  "User",
		"email":      email,
		"password":   password,
	})
	if err != nil {
		return nil, errors.New("failed to create user")
	}
	usrID := &resp.ID
	return usrID, nil
}

func userTokenFactory() (*string, error) {
	newUUID, err := uuid.NewV4()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error generating uuid %s", err.Error()))
	}
	email := fmt.Sprintf("%s@provide-integration-tests.com", newUUID.String())
	password := fmt.Sprintf("%s", newUUID.String())

	userID, err := userFactory(email, password)
	if err != nil || userID == nil {
		return nil, err
	}

	resp, err := ident.Authenticate(email, password)
	if err != nil {
		return nil, errors.New("failed to authenticate user")
	}
	return resp.Token.Token, nil
}

func init() {
	token, err := userTokenFactory()
	if err != nil {
		log.Printf("failed to create token; %s", err.Error())
		return
	}

	//test getting a new unsealer key
	newkeyresp, err := provide.GenerateSeal(*token, map[string]interface{}{})
	if err != nil {
		log.Printf("error generating new unsealer key %s", err.Error())
	}
	log.Printf("newkeyresp: %+v", *newkeyresp)
	log.Printf("newly generated unsealer key %s", *newkeyresp.UnsealerKey)
	log.Printf("newly generated unsealer key hash %s", *newkeyresp.ValidationHash)

	_, err = provide.Unseal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		log.Printf("**vault not unsealed**. error: %s", err.Error())
		return
	}

	// now try it again, and we expect a 204 (no response) when trying to unseal a sealed vault
	_, err = provide.Unseal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		log.Printf("**second unseal attempt failed when it should pass**. error: %s", err.Error())
		return
	}

}

func unsealVault() error {
	token, err := userTokenFactory()
	if err != nil {
		return fmt.Errorf("failed to create token; %s", err.Error())

	}

	_, err = provide.Unseal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		return fmt.Errorf("**vault not unsealed**. error: %s", err.Error())
	}
	return nil
}

func TestSealUnsealer(t *testing.T) {
	// we're going to unseal the vault,
	// do an operation
	// seal the vault
	// retry operation, expect it to fail
	// unseal the vault, retry operation and expect it to succeed

	//get the vault unsealed to make sure other tests can continue
	defer unsealVault()

	token, err := userTokenFactory()
	if err != nil {
		log.Printf("failed to create token; %s", err.Error())
		return
	}

	_, err = provide.Unseal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		t.Errorf("**vault not unsealed**. error: %s", err.Error())
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	_, err = provide.Seal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		t.Errorf("**vault not sealed**. error: %s", err.Error())
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err == nil {
		t.Errorf("performed operation while sealed!")
		return
	}

	_, err = provide.Unseal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		t.Errorf("**vault not unsealed**. error: %s", err.Error())
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	// now we'll try to seal it badly and expect it to continue working
	_, err = provide.Seal(*token, map[string]interface{}{
		"key": "raffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err == nil {
		t.Errorf("**vault sealed with bad key**")
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	// now we'll seal it and unseal it badly and expect it to fail
	_, err = provide.Seal(*token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		t.Errorf("**vault not sealed**. error: %s", err.Error())
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err == nil {
		t.Errorf("performed operation while sealed!")
		return
	}

	_, err = provide.Unseal(*token, map[string]interface{}{
		"key": "raffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err == nil {
		t.Errorf("unsealed vault with bad key.")
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err == nil {
		t.Errorf("created vault while sealed!")
		return
	}

}

func TestAPICreateVault(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	_, err = vaultFactory(*token, "vaulty vault", "just a boring vaulty vault")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

}

func TestAPICreateKey(t *testing.T) {
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

	_, err = provide.CreateKey(*token, vault.ID.String(), map[string]interface{}{
		"type":        "asymmetric",
		"usage":       "sign/verify",
		"spec":        "secp256k1",
		"name":        "integration test ethereum key",
		"description": "organization eth/stablecoin wallet",
	})

	if err != nil {
		t.Errorf("failed to create key error: %s", err.Error())
		return
	}
}

func TestAPIDeleteKey(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "secp256k1", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	err = provide.DeleteKey(*token, vault.ID.String(), key.ID.String())
	if err != nil {
		t.Errorf("failed to delete key for vault: %s", err.Error())
		return
	}
}

func TestAPISign(t *testing.T) {

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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "secp256k1", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(32)
	payload := hex.EncodeToString(payloadBytes)
	_, err = provide.SignMessage(*token, vault.ID.String(), key.ID.String(), payload, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	// TODO check for signature in response, not sure if the errors are actually tripping
}

func TestAPIVerifySecp256k1Signature(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecECCSecp256k1, "namey name", "cute description")
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

	t.Logf("******* signresponse: %+v", sigresponse)

	//ensure we haven't returned a derivation path
	if sigresponse.DerivationPath != nil {
		t.Errorf("Derivation path present for non-derived key, path %s", *sigresponse.DerivationPath)
		return
	}

	//ensure we haven't returned an address
	if sigresponse.Address != nil {
		t.Errorf("address present for non-derived key, address %s", *sigresponse.Address)
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

func TestAPIVerifyEd25519Signature(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecECCEd25519, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(1000)
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

func TestAPIVerifyRSA2048PS256Signature(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", cryptovault.KeySpecRSA2048, "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	payloadBytes, _ := common.RandomBytes(1000)
	messageToSign := hex.EncodeToString(payloadBytes)

	opts := map[string]interface{}{}
	json.Unmarshal([]byte(`{"algorithm":"PS256"}`), &opts)

	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, opts)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, opts)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != true {
		t.Error("failed to verify signature for vault")
		return
	}

}

func TestAPIEncrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)
	nonce := "1"

	_, err = provide.EncryptWithNonce(*token, vault.ID.String(), key.ID.String(), data, nonce)

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}
}

func TestAPIChachaDecrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "ChaCha20", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)
	nonce := "1"

	encryptedDataResponse, err := provide.EncryptWithNonce(*token, vault.ID.String(), key.ID.String(), data, nonce)

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})

	if decryptedDataResponse.Data != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedDataResponse.Data)
		return
	}
}

func TestAPIDecrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)
	nonce := common.RandomString(12)

	encryptedDataResponse, err := provide.EncryptWithNonce(*token, vault.ID.String(), key.ID.String(), data, nonce)

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})

	if decryptedDataResponse.Data != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedDataResponse.Data)
		return
	}
}

func TestAPIDecryptNoNonce(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	data := common.RandomString(128)

	encryptedDataResponse, err := provide.Encrypt(*token, vault.ID.String(), key.ID.String(), data)

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})

	if decryptedDataResponse.Data != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedDataResponse.Data)
		return
	}
}

func TestCreateHDWallet(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "BIP39", "hdwallet", "integration test hd wallet")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	if key.PublicKey == nil {
		t.Errorf("failed to assign xpub key on hd wallet; %s", key.ID)
		return
	}

	opts := map[string]interface{}{}
	json.Unmarshal([]byte(`{"hdwallet":{"coin":60, "index":0}}`), &opts)

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, opts)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, opts)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != true {
		t.Errorf("failed to verify signature for vault")
		return
	}
}

func TestCreateHDWalletFailsWithInvalidCoin(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "BIP39", "hdwallet", "integration test hd wallet")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	if key.PublicKey == nil {
		t.Errorf("failed to assign xpub key on hd wallet; %s", key.ID)
		return
	}

	opts := map[string]interface{}{}
	json.Unmarshal([]byte(`{"hdwallet":{"coin":61, "index":0}}`), &opts) // coin: 61 <-- this is not supported

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, opts)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, opts)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != true {
		t.Errorf("failed to verify signature for vault")
		return
	}
}

func TestCreateHDWalletCoinAbbr(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "BIP39", "hdwallet", "integration test hd wallet")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	if key.PublicKey == nil {
		t.Errorf("failed to assign xpub key on hd wallet; %s", key.ID)
		return
	}

	opts := map[string]interface{}{}
	json.Unmarshal([]byte(`{"hdwallet":{"coin_abbr":"ETH", "index":0}}`), &opts)

	payloadBytes, _ := common.RandomBytes(32)
	messageToSign := hex.EncodeToString(payloadBytes)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, opts)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, opts)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	if verifyresponse.Verified != true {
		t.Errorf("failed to verify signature for vault")
		return
	}
}

func TestHDWalletAutoSign(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "BIP39", "hdwallet", "integration test hd wallet")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	for iteration := 0; iteration < 10; iteration++ {
		payloadBytes, _ := common.RandomBytes(32)
		messageToSign := hex.EncodeToString(payloadBytes)
		sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
		if err != nil {
			t.Errorf("failed to sign message %s", err.Error())
			return
		}

		//ensure we have returned a derivation path
		if sigresponse.DerivationPath == nil {
			t.Errorf("No derivation path returned for derived key sign operation")
			return
		}

		//ensure we have returned an address
		if sigresponse.Address == nil {
			t.Errorf("no address returned for derived key sign operation")
			return
		}

		// set up the verification options
		opts := map[string]interface{}{}
		options := fmt.Sprintf(`{"hdwallet":{"coin_abbr":"ETH", "index":%d}}`, iteration)
		json.Unmarshal([]byte(options), &opts)

		verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, *sigresponse.Signature, opts)
		if err != nil {
			t.Errorf("failed to verify signature for vault: %s", err.Error())
			return
		}

		if verifyresponse.Verified != true {
			t.Errorf("failed to verify signature for vault!")
			return
		}
	}
}

func TestListKeys(t *testing.T) {
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

	// set how many keys we're going to generate
	const numberOfKeys = 24
	var inputKey [numberOfKeys + 1]*provide.Key
	inputKey[0] = nil //ignoring the vault master key

	for looper := 1; looper <= numberOfKeys; looper++ {
		keyName := fmt.Sprintf("integration test ethereum key %d", looper)
		key, err := provide.CreateKey(*token, vault.ID.String(), map[string]interface{}{
			"type":        "asymmetric",
			"usage":       "sign/verify",
			"spec":        "secp256k1",
			"name":        keyName,
			"description": "organization eth/stablecoin wallet",
		})

		if err != nil {
			t.Errorf("failed to create key. error %s", err.Error())
		}

		inputKey[looper] = key

		if len(*inputKey[looper].Address) != 42 {
			t.Errorf("invalid address length for key 01. expected 42, got %d", len(*inputKey[looper].Address))
			return
		}
	}

	listVaultKeysResponse, err := provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != numberOfKeys+1 {
		t.Errorf("invalid number of keys returned")
		return
	}

	var outputKey [numberOfKeys + 1]*provide.Key
	for looper := 0; looper <= numberOfKeys; looper++ {
		outputKey[looper] = listVaultKeysResponse[looper]

		if looper > 0 {
			if *inputKey[looper].Address != *outputKey[looper].Address {
				t.Errorf("address mismatch. expected %s, got %s", *inputKey[looper].Address, *outputKey[looper].Address)
			}

			if *inputKey[looper].Description != *outputKey[looper].Description {
				t.Errorf("description mismatch. expected %s, got %s", *inputKey[looper].Description, *outputKey[looper].Description)
			}

			if inputKey[looper].ID != outputKey[looper].ID {
				t.Errorf("id mismatch. expected %s, got %s", inputKey[looper].ID, outputKey[looper].ID)
			}

			if *inputKey[looper].Name != *outputKey[looper].Name {
				t.Errorf("name mismatch. expected %s, got %s", *inputKey[looper].Name, *outputKey[looper].Name)
			}

			if *inputKey[looper].Spec != *outputKey[looper].Spec {
				t.Errorf("spec mismatch. expected %s, got %s", *inputKey[looper].Spec, *outputKey[looper].Spec)
			}

			if *inputKey[looper].Type != *outputKey[looper].Type {
				t.Errorf("type mismatch. expected %s, got %s", *inputKey[looper].Type, *outputKey[looper].Type)
			}

			if *inputKey[looper].Usage != *outputKey[looper].Usage {
				t.Errorf("usage mismatch. expected %s, got %s", *inputKey[looper].Usage, *outputKey[looper].Usage)
			}

			if inputKey[looper].VaultID.String() != outputKey[looper].VaultID.String() {
				t.Errorf("vault_id mismatch. expected %s, got %s", inputKey[looper].VaultID, outputKey[looper].VaultID)
			}

			if *inputKey[looper].PublicKey != *outputKey[looper].PublicKey {
				t.Errorf("public_key mismatch. expected %s, got %s", *inputKey[looper].PublicKey, *outputKey[looper].PublicKey)
			}

			t.Logf("key %d of %d validated", looper, numberOfKeys)
		}
	}
}

func TestListKeys_Filtered(t *testing.T) {
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

	// generate a key that will be filtered out
	_, err = provide.CreateKey(*token, vault.ID.String(), map[string]interface{}{
		"type":        "asymmetric",
		"usage":       "sign/verify",
		"spec":        "babyJubJub",
		"name":        "babyjubjub key to be filtered out",
		"description": "baseline babyjubjub key",
	})

	if err != nil {
		t.Errorf("failed to create key. error %s", err.Error())
	}

	// set how many keys we're going to generate for the filter
	const numberOfKeys = 2
	var inputKey [numberOfKeys + 1]*provide.Key
	//inputKey[0] = nil //ignoring the vault master key

	for looper := 0; looper < numberOfKeys; looper++ {
		keyName := fmt.Sprintf("integration test ethereum key %d", looper)
		key, err := provide.CreateKey(*token, vault.ID.String(), map[string]interface{}{
			"type":        "asymmetric",
			"usage":       "sign/verify",
			"spec":        "secp256k1",
			"name":        keyName,
			"description": "organization eth/stablecoin wallet",
		})

		if err != nil {
			t.Errorf("failed to create key. error %s", err.Error())
		}

		inputKey[looper] = key

		if len(*inputKey[looper].Address) != 42 {
			t.Errorf("invalid address length for key 01. expected 42, got %d", len(*inputKey[looper].Address))
			return
		}
	}

	// first run without filter
	listVaultKeysResponse, err := provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != numberOfKeys+2 {
		t.Errorf("invalid number of keys returned")
		return
	}

	// now filter to just secp256k1
	listVaultKeysResponse, err = provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{
		"spec": "secp256k1",
	})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != numberOfKeys {
		t.Errorf("invalid number of secp256k1 keys returned")
		return
	}

	// now filter to babyjubjub
	listVaultKeysResponse, err = provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{
		"spec": "babyJubJub",
	})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != 1 {
		t.Errorf("invalid number of baby jub jub keys returned")
		return
	}

	// now filter to symmetric (should be just the master key)
	listVaultKeysResponse, err = provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{
		"type": "symmetric",
	})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != 1 {
		t.Errorf("invalid number of symmetric keys returned")
		return
	}

	// now filter to asymmetric (should be babyjubjub + numberOfKeys secp256k1 keys)
	listVaultKeysResponse, err = provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{
		"type": "asymmetric",
	})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != (numberOfKeys + 1) {
		t.Errorf("invalid number of asymmetric keys returned")
		return
	}

	//now check the value of all the secp256k1 keys added
	// now filter to babyjubjub
	listVaultKeysResponse, err = provide.ListKeys(*token, vault.ID.String(), map[string]interface{}{
		"spec": "secp256k1",
	})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	if len(listVaultKeysResponse) != numberOfKeys {
		t.Errorf("invalid number of secp256k1 keys returned")
		return
	}

	var outputKey [numberOfKeys + 1]*provide.Key
	for looper := 0; looper < numberOfKeys; looper++ {
		outputKey[looper] = listVaultKeysResponse[looper]

		if *inputKey[looper].Address != *outputKey[looper].Address {
			t.Errorf("address mismatch. expected %s, got %s", *inputKey[looper].Address, *outputKey[looper].Address)
		}

		if *inputKey[looper].Description != *outputKey[looper].Description {
			t.Errorf("description mismatch. expected %s, got %s", *inputKey[looper].Description, *outputKey[looper].Description)
		}

		if inputKey[looper].ID != outputKey[looper].ID {
			t.Errorf("id mismatch. expected %s, got %s", inputKey[looper].ID, outputKey[looper].ID)
		}

		if *inputKey[looper].Name != *outputKey[looper].Name {
			t.Errorf("name mismatch. expected %s, got %s", *inputKey[looper].Name, *outputKey[looper].Name)
		}

		if *inputKey[looper].Spec != *outputKey[looper].Spec {
			t.Errorf("spec mismatch. expected %s, got %s", *inputKey[looper].Spec, *outputKey[looper].Spec)
		}

		if *inputKey[looper].Type != *outputKey[looper].Type {
			t.Errorf("type mismatch. expected %s, got %s", *inputKey[looper].Type, *outputKey[looper].Type)
		}

		if *inputKey[looper].Usage != *outputKey[looper].Usage {
			t.Errorf("usage mismatch. expected %s, got %s", *inputKey[looper].Usage, *outputKey[looper].Usage)
		}

		if inputKey[looper].VaultID.String() != outputKey[looper].VaultID.String() {
			t.Errorf("vault_id mismatch. expected %s, got %s", inputKey[looper].VaultID, outputKey[looper].VaultID)
		}

		if *inputKey[looper].PublicKey != *outputKey[looper].PublicKey {
			t.Errorf("public_key mismatch. expected %s, got %s", *inputKey[looper].PublicKey, *outputKey[looper].PublicKey)
		}

		t.Logf("key %d of %d validated", looper+1, numberOfKeys)
	}
}

func TestAPIDerivedChachaDecrypt(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "ChaCha20", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	nonce := 1
	context := common.RandomString(32)
	name := "derived key 01"
	description := "derived key 01 description"

	derivedKey, err := provide.DeriveVaultKey(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"nonce":       nonce,
		"context":     context,
		"name":        name,
		"description": description,
	})

	if err != nil {
		t.Errorf("failed to derive key for vault: %s", vault.ID)
		return
	}

	if *derivedKey.Name != name {
		t.Errorf("name field incorrect. expected %s, got %s", name, *derivedKey.Name)
		return
	}

	if *derivedKey.Description != description {
		t.Errorf("description field incorrect. expected %s, got %s", description, *derivedKey.Description)
		return
	}

	data := common.RandomString(128)

	encryptedDataResponse, err := provide.Encrypt(*token, derivedKey.VaultID.String(), derivedKey.ID.String(), data)

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, derivedKey.VaultID.String(), derivedKey.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})

	if decryptedDataResponse.Data != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedDataResponse.Data)
		return
	}
}

func TestAPIDerivedChachaDecryptNoNonce(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "ChaCha20", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	context := common.RandomString(32)
	name := "derived key 01"
	description := "derived key 01 description"

	derivedKey, err := provide.DeriveVaultKey(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"context":     context,
		"name":        name,
		"description": description,
	})

	if err != nil {
		t.Errorf("failed to derive key for vault: %s", vault.ID)
		return
	}

	if *derivedKey.Name != name {
		t.Errorf("name field incorrect. expected %s, got %s", name, *derivedKey.Name)
		return
	}

	if *derivedKey.Description != description {
		t.Errorf("description field incorrect. expected %s, got %s", description, *derivedKey.Description)
		return
	}

	data := common.RandomString(128)

	encryptedDataResponse, err := provide.Encrypt(*token, derivedKey.VaultID.String(), derivedKey.ID.String(), data)

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, derivedKey.VaultID.String(), derivedKey.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})

	if decryptedDataResponse.Data != data {
		t.Errorf("decrypted data mismatch, expected %s, got %s", data, decryptedDataResponse.Data)
		return
	}
}

func TestAPIDerivedNonChachaDecryptNoNonce(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "symmetric", "encrypt/decrypt", "AES-256-GCM", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	context := common.RandomString(32)
	name := "derived key 01"
	description := "derived key 01 description"

	_, err = provide.DeriveVaultKey(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"context":     context,
		"name":        name,
		"description": description,
	})

	if err == nil {
		t.Errorf("incorrectly derived non-chacha20 key for vault: %s", vault.ID)
		return
	}

	if err != nil {
		t.Logf("correctly returned error deriving non-chacha20 key. Error: %s", err.Error())
	}
}

func TestAPIDeriveBIP39(t *testing.T) {
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

	key, err := keyFactory(*token, vault.ID.String(), "asymmetric", "sign/verify", "BIP39", "namey name", "cute description")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	derivedKey, err := provide.DeriveKey(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{})

	if err != nil {
		t.Errorf("failed to derive key for vault: %s", vault.ID)
		return
	}

	if derivedKey.Address == nil {
		t.Errorf("address should be non-nil for derived secp256k1 BIP39 HD wallet key")
		return
	}

	if derivedKey.HDDerivationPath == nil {
		t.Errorf("derivation path should be non-nil for derived secp256k1 BIP39 HD wallet key")
		return
	}

	if derivedKey.PublicKey == nil {
		t.Errorf("public key should be non-nil for derived secp256k1 BIP39 HD wallet key")
		return
	}
}

func TestEphemeralCreation(t *testing.T) {
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

	tt := []struct {
		Name        string
		Description string
		Type        string
		Usage       string
		Spec        string
	}{
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "C25519"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "Ed25519"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "secp256k1"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "babyJubJub"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "BIP39"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "RSA-2048"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "RSA-3072"},
		{"ephemeral key", "ephemeral key description", "asymmetric", "sign/verify", "RSA-4096"},
		{"ephemeral key", "ephemeral key description", "symmetric", "encrypt/decrypt", "AES-256-GCM"},
		{"ephemeral key", "ephemeral key description", "symmetric", "encrypt/decrypt", "ChaCha20"},
	}

	for _, tc := range tt {
		key, err := keyFactoryEphemeral(*token, vault.ID.String(), tc.Type, tc.Usage, tc.Spec, tc.Name, tc.Description)
		if err != nil {
			t.Errorf("failed to create key; %s", err.Error())
			return
		}

		if *key.Name != tc.Name {
			t.Errorf("name mismatch. expected %s, got %s", tc.Name, *key.Name)
			return
		}

		if *key.Description != tc.Description {
			t.Errorf("description mismatch. expected %s, got %s", tc.Description, *key.Description)
			return
		}

		if *key.Type != tc.Type {
			t.Errorf("type mismatch. expected %s, got %s", tc.Type, *key.Type)
			return
		}

		if *key.Usage != tc.Usage {
			t.Errorf("usage mismatch. expected %s, got %s", tc.Usage, *key.Usage)
			return
		}
		if *key.Spec != tc.Spec {
			t.Errorf("spec mismatch. expected %s, got %s", tc.Spec, *key.Spec)
			return
		}

		switch tc.Spec {
		case "C25519":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
		case "Ed25519":
			if key.Seed == nil {
				t.Errorf("no seed returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
		case "secp256k1":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
			if key.Address == nil {
				t.Errorf("no address returned for ephemeral %s key", tc.Spec)
			}
		case "babyJubJub":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "BIP39":
			if key.Seed == nil {
				t.Errorf("no seed returned for ephemeral %s key", tc.Spec)
			}
		case "RSA-2048":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "RSA-3072":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "RSA-4096":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "AES-256-GCM":
			if key.PrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
		case "ChaCha20":
			if key.Seed == nil {
				t.Errorf("no seed returned for ephemeral %s key", tc.Spec)
			}
		default:
			t.Errorf("unknown key spec generated: %s", tc.Spec)
			return
		}
	}
}

func TestNonEphemeralCreation(t *testing.T) {
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

	tt := []struct {
		Name        string
		Description string
		Type        string
		Usage       string
		Spec        string
	}{
		{"regular key", "regular key description", "asymmetric", "sign/verify", "C25519"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "Ed25519"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "secp256k1"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "babyJubJub"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "BIP39"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "RSA-2048"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "RSA-3072"},
		{"regular key", "regular key description", "asymmetric", "sign/verify", "RSA-4096"},
		{"regular key", "regular key description", "symmetric", "encrypt/decrypt", "AES-256-GCM"},
		{"regular key", "regular key description", "symmetric", "encrypt/decrypt", "ChaCha20"},
	}

	for _, tc := range tt {
		key, err := keyFactory(*token, vault.ID.String(), tc.Type, tc.Usage, tc.Spec, tc.Name, tc.Description)
		if err != nil {
			t.Errorf("failed to create key; %s", err.Error())
			return
		}

		if *key.Name != tc.Name {
			t.Errorf("name mismatch. expected %s, got %s", tc.Name, *key.Name)
			return
		}

		if *key.Description != tc.Description {
			t.Errorf("description mismatch. expected %s, got %s", tc.Description, *key.Description)
			return
		}

		if *key.Type != tc.Type {
			t.Errorf("type mismatch. expected %s, got %s", tc.Type, *key.Type)
			return
		}

		if *key.Usage != tc.Usage {
			t.Errorf("usage mismatch. expected %s, got %s", tc.Usage, *key.Usage)
			return
		}
		if *key.Spec != tc.Spec {
			t.Errorf("spec mismatch. expected %s, got %s", tc.Spec, *key.Spec)
			return
		}

		switch tc.Spec {
		case "C25519":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no private key returned for regular %s key", tc.Spec)
			}
		case "Ed25519":
			if key.Seed != nil {
				t.Errorf("seed returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no private key returned for regular %s key", tc.Spec)
			}
		case "secp256k1":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for regular %s key", tc.Spec)
			}
			if key.Address == nil {
				t.Errorf("no address returned for regular %s key", tc.Spec)
			}
		case "babyJubJub":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for regular %s key", tc.Spec)
			}
		case "BIP39":
			if key.Seed != nil {
				t.Errorf("seed returned for regular %s key", tc.Spec)
			}
		case "RSA-2048":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for regular %s key", tc.Spec)
			}
		case "RSA-3072":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for regular %s key", tc.Spec)
			}
		case "RSA-4096":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for regular %s key", tc.Spec)
			}
		case "AES-256-GCM":
			if key.PrivateKey != nil {
				t.Errorf("private key returned for regular %s key", tc.Spec)
			}
		case "ChaCha20":
			if key.Seed != nil {
				t.Errorf("seed returned for regular %s key", tc.Spec)
			}
		default:
			t.Errorf("unknown key spec generated: %s", tc.Spec)
			return
		}
	}
}

// +build integration

package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"testing"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/vault"
	cryptovault "github.com/provideapp/vault/vault"
	ident "github.com/provideservices/provide-go/api/ident"
	provide "github.com/provideservices/provide-go/api/vault"
)

func keyFactory(token, vaultID, keyType, keyUsage, keySpec, keyName, keyDescription string) (*vault.Key, error) {

	resp, err := provide.CreateVaultKey(token, vaultID, map[string]interface{}{
		"type":        keyType,
		"usage":       keyUsage,
		"spec":        keySpec,
		"name":        keyName,
		"description": keyDescription,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create key error: %s", err.Error())
	}

	key := &vault.Key{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall key data: %s", err.Error())
	}
	json.Unmarshal(respRaw, &key)
	return key, nil
}

func vaultFactory(token, name, desc string) (*vault.Vault, error) {
	resp, err := provide.CreateVault(token, map[string]interface{}{
		"name":        name,
		"description": desc,
	})
	if err != nil {
		return nil, err
	}
	vlt := &vault.Vault{}
	respRaw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(respRaw, &vlt)
	return vlt, nil
}

func userFactory(email, password string) (*uuid.UUID, error) {
	status, resp, err := ident.CreateUser("", map[string]interface{}{
		"first_name": "A",
		"last_name":  "User",
		"email":      email,
		"password":   password,
	})
	if err != nil || status != 201 {
		return nil, errors.New("failed to create user")
	}
	var usrID *uuid.UUID
	if usr, usrOk := resp.(map[string]interface{}); usrOk {
		if id, idok := usr["id"].(string); idok {
			usrUUID, err := uuid.FromString(id)
			if err != nil {
				return nil, err
			}
			usrID = &usrUUID
		}
	}
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

	status, resp, err := ident.Authenticate(email, password)
	if err != nil || status != 201 {
		return nil, errors.New("failed to authenticate user")
	}
	var token *string
	if authresp, authrespOk := resp.(map[string]interface{}); authrespOk {
		if tok, tokOk := authresp["token"].(map[string]interface{}); tokOk {
			if tokenstr, tokenstrOk := tok["token"].(string); tokenstrOk {
				token = common.StringOrNil(tokenstr)
			}
		}
	}
	return token, nil
}

func init() {
	token, err := userTokenFactory()
	if err != nil {
		log.Printf("failed to create token; %s", err.Error())
		return
	}

	// _, createresp, err := provide.GenerateSeal(*token, map[string]interface{}{})
	// //assert type to get something sensible from empty interface
	// response, _ := createresp.(map[string]interface{})
	// log.Printf("response from create sealer: %+v", response)

	// if err != nil {
	// 	log.Printf("error unsealing vault %s", err.Error())
	// }

	unsealresp, err := provide.UnsealVault(*token, map[string]interface{}{
		"unsealer_key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		log.Printf("*************************vault not unsealed****************************************")
		return
	}
	//response, _ := unsealresp.(map[string]interface{})
	log.Printf("response from unseal vault: %+v", unsealresp)

	log.Printf("vault unsealed")
}
func TestAPICreateVault(t *testing.T) {
	token, err := userTokenFactory()
	if err != nil {
		t.Errorf("failed to create token; %s", err.Error())
		return
	}

	// _, sealresp, err := provide.UnsealVault(*token, map[string]interface{}{
	// 	"unsealerkey": "0x53534144444f374f4c544849564a5146465950434c353645454a344856594134",
	// })

	// //assert type to get something sensible from empty interface
	// response, _ := sealresp.(map[string]interface{})
	// t.Logf("response from unsealer: %+v", response)

	// if err != nil {
	// 	t.Errorf("error unsealing vault %s", err.Error())
	// }

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

	// _, _, err = provide.UnsealVault(*token, map[string]interface{}{
	// 	"unsealerkey": "53534144444f374f4c544849564a5146465950434c353645454a344856594134",
	// })
	// if err != nil {
	// 	t.Errorf("error unsealing vault %s", err.Error())
	// }

	vault, err := vaultFactory(*token, "vaulty vault", "just a vault with a key")
	if err != nil {
		t.Errorf("failed to create vault; %s", err.Error())
		return
	}

	_, err = provide.CreateVaultKey(*token, vault.ID.String(), map[string]interface{}{
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

	err = provide.DeleteVaultKey(*token, vault.ID.String(), key.ID.String())
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

	_, err = provide.SignMessage(*token, vault.ID.String(), key.ID.String(), "hello world", nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
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

	messageToSign := common.RandomString(1000)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
	// TODO fix these so they work with the new data returned
	// //assert type to get something sensible from empty interface
	// response, _ := sigresponse.(map[string]interface{})

	// //ensure we haven't returned a derivation path
	// if response["hd_derivation_path"] != nil {
	// 	t.Logf("response: %+v", response)
	// 	t.Errorf("Derivation path present for non-derived key, path %s", response["hd_derivation_path"])
	// 	return
	// }

	// //ensure we haven't returned an address
	// if response["address"] != nil {
	// 	t.Logf("response: %+v", response)
	// 	t.Errorf("address present for non-derived key, address %s", response["address"])
	// 	return
	// }

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, sigresponse.Signature, nil)
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

	messageToSign := common.RandomString(1000)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
	// //assert type to get something sensible from empty interface
	// response, _ := sigresponse.(map[string]interface{})

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, sigresponse.Signature, nil)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}
	// response, _ = verifyresponse.(map[string]interface{})
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

	messageToSign := common.RandomString(1000)

	opts := map[string]interface{}{}
	json.Unmarshal([]byte(`{"algorithm":"PS256"}`), &opts)

	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, opts)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}

	//assert type to get something sensible from empty interface
	//response, _ := sigresponse.(map[string]interface{})

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, sigresponse.Signature, opts)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}

	//response, _ = verifyresponse.(map[string]interface{})
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

	//encryptedData, _ := encryptedDataResponse.(map[string]interface{})

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})
	//decryptedData, _ := decryptedDataResponse.(map[string]interface{})

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

	//encryptedData, _ := encryptedDataResponse.(map[string]interface{})

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})

	//decryptedData, _ := decryptedDataResponse.(map[string]interface{})

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

	//encryptedData, _ := encryptedDataResponse.(map[string]interface{})

	if err != nil {
		t.Errorf("failed to encrypt message for vault: %s", vault.ID)
		return
	}

	decryptedDataResponse, err := provide.Decrypt(*token, vault.ID.String(), key.ID.String(), map[string]interface{}{
		"data": encryptedDataResponse.Data,
	})
	//decryptedData, _ := decryptedDataResponse.(map[string]interface{})

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

	key, err := keyFactory(*token, vault.ID.String(), "hdwallet", "EthHdWallet", "BIP39", "hdwallet", "integration test hd wallet")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	opts := map[string]interface{}{}
	json.Unmarshal([]byte(`{"hdwallet":{"coin":"ETH", "index":0}}`), &opts)

	messageToSign := common.RandomString(1000)
	sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, opts)
	if err != nil {
		t.Errorf("failed to sign message %s", err.Error())
		return
	}
	//assert type to get something sensible from empty interface
	//response, _ := sigresponse.(map[string]interface{})

	verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, sigresponse.Signature, opts)
	if err != nil {
		t.Errorf("failed to verify signature for vault: %s", err.Error())
		return
	}
	//assert type to get something sensible from empty interface
	//response, _ = verifyresponse.(map[string]interface{})
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

	key, err := keyFactory(*token, vault.ID.String(), "hdwallet", "EthHdWallet", "BIP39", "hdwallet", "integration test hd wallet")
	if err != nil {
		t.Errorf("failed to create key; %s", err.Error())
		return
	}

	for iteration := 0; iteration < 10; iteration++ {
		messageToSign := common.RandomString(1000)
		sigresponse, err := provide.SignMessage(*token, vault.ID.String(), key.ID.String(), messageToSign, nil)
		if err != nil {
			t.Errorf("failed to sign message %s", err.Error())
			return
		}
		//assert type to get something sensible from empty interface
		//response, _ := sigresponse.(map[string]interface{})

		//ensure we have returned a derivation path
		//TODO get the derivation path from the response
		// if sigresponse.opts["hd-derivation-path"] == nil {
		// 	t.Errorf("No derivation path returned for derived key sign operation")
		// 	return
		// }

		//ensure we have returned an address
		//TODO get the address from the sig response
		// if sigresponse.address == nil {
		// 	t.Errorf("no address returned for derived key sign operation")
		// 	return
		// }

		// set up the verification options
		opts := map[string]interface{}{}
		options := fmt.Sprintf(`{"hdwallet":{"coin":"ETH", "index":%d}}`, iteration)
		json.Unmarshal([]byte(options), &opts)

		verifyresponse, err := provide.VerifySignature(*token, vault.ID.String(), key.ID.String(), messageToSign, sigresponse.Signature, opts)
		if err != nil {
			t.Errorf("failed to verify signature for vault: %s", err.Error())
			return
		}
		//assert type to get something sensible from empty interface and check the verified value
		//response, _ = verifyresponse.(map[string]interface{})
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
		key, err := provide.CreateVaultKey(*token, vault.ID.String(), map[string]interface{}{
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

		//TODO check Address is returned in object
		// if len(response[looper].Address) != 42 {
		// 	t.Errorf("invalid address length for key 01. expected 42, got %d", len(inputKey[looper]["address"].(string)))
		// }
	}

	listVaultKeysResponse, err := provide.ListVaultKeys(*token, vault.ID.String(), map[string]interface{}{})
	if err != nil {
		t.Errorf("failed to list keys. error %s", err.Error())
	}

	//assert type to get something sensible from empty interface
	//listOfKeys := listVaultKeysResponse.([]interface{})

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

			if inputKey[looper].VaultID != outputKey[looper].VaultID {
				t.Errorf("vault_id mismatch. expected %s, got %s", inputKey[looper].VaultID, outputKey[looper].VaultID)
			}

			if *inputKey[looper].PublicKey != *outputKey[looper].PublicKey {
				t.Errorf("public_key mismatch. expected %s, got %s", *inputKey[looper].PublicKey, *outputKey[looper].PublicKey)
			}

			t.Logf("key %d of %d validated", looper, numberOfKeys)
		}
	}
}

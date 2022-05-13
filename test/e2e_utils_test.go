/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// +build integration vault secret bls

package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/ident/common"
	ident "github.com/provideplatform/provide-go/api/ident"
	provide "github.com/provideplatform/provide-go/api/vault"
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
	common.Log.Debugf("resp is %+v", resp)
	return resp.Token.AccessToken, nil
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

	_, err = provide.Unseal(token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		log.Printf("**vault not unsealed**. error: %s", err.Error())
		return
	}

	// now try it again, and we expect a 204 (no response) when trying to unseal a sealed vault
	_, err = provide.Unseal(token, map[string]interface{}{
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

	_, err = provide.Unseal(token, map[string]interface{}{
		"key": "traffic charge swing glimpse will citizen push mutual embrace volcano siege identify gossip battle casual exit enrich unlock muscle vast female initial please day",
	})
	if err != nil {
		return fmt.Errorf("**vault not unsealed**. error: %s", err.Error())
	}
	return nil
}

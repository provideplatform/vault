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

// +build unit

package test

import (
	"testing"

	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/vault/vault"
)

var ephDB = dbconf.DatabaseConnection()

func TestEphemeralCreation(t *testing.T) {
	vlt := vaultFactory()
	if vlt.ID == uuid.Nil {
		t.Error("vault not created")
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
		key, err := vault.NewEphemeralKey(&vlt.ID, tc.Name, tc.Description, tc.Type, tc.Usage, tc.Spec)
		if err != nil {
			t.Errorf("ephemeral key creation failed. Error: %s", err.Error())
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
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "Ed25519":
			if key.EphemeralSeed == nil {
				t.Errorf("no seed returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "secp256k1":
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "babyJubJub":
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "BIP39":
			if key.EphemeralSeed == nil {
				t.Errorf("no seed returned for ephemeral %s key", tc.Spec)
			}
		case "RSA-2048":
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "RSA-3072":
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "RSA-4096":
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
			if key.PublicKey == nil {
				t.Errorf("no public key returned for ephemeral %s key", tc.Spec)
			}
		case "AES-256-GCM":
			if key.EphemeralPrivateKey == nil {
				t.Errorf("no private key returned for ephemeral %s key", tc.Spec)
			}
		case "ChaCha20":
			if key.EphemeralSeed == nil {
				t.Errorf("no seed returned for ephemeral %s key", tc.Spec)
			}
		default:
			t.Errorf("unknown key spec generated: %s", tc.Spec)
			return
		}
	}
}

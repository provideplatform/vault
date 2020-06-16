package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
	vaultcrypto "github.com/provideapp/vault/vault/crypto"
	provide "github.com/provideservices/provide-go"
	"golang.org/x/crypto/chacha20"
)

const defaultVaultMasterKeyName = "master0"

// KeyTypeAsymmetric asymmetric key type
const KeyTypeAsymmetric = "asymmetric"

// KeyTypeSymmetric symmetric key type
const KeyTypeSymmetric = "symmetric"

// KeyUsageEncryptDecrypt encrypt/decrypt usage
const KeyUsageEncryptDecrypt = "encrypt/decrypt"

// KeyUsageSignVerify sign/verify usage
const KeyUsageSignVerify = "sign/verify"

// KeySpecAES256GCM AES-256-GCM key spec
const KeySpecAES256GCM = "AES-256-GCM"

// KeySpecChaCha20 ChaCha20 key spec
const KeySpecChaCha20 = "ChaCha20"

// KeySpecECCBabyJubJub babyJubJub key spec
const KeySpecECCBabyJubJub = "babyJubJub"

// KeySpecECCC25519 C25519 key spec
const KeySpecECCC25519 = "C25519"

// KeySpecECCEd25519 Ed25519 key spec
const KeySpecECCEd25519 = "Ed25519"

// KeySpecECCSecp256k1 secp256k1 key spec
const KeySpecECCSecp256k1 = "secp256k1"

// const KeySpecECCSecp256r1 = "ECC-NIST-P256"
// const KeySpecECCSecp2048 = "ECC-NIST-P384"
// const KeySpecECCSecp521r1 = "ECC-NIST-P521"
// const KeySpecECCSecpP256k1 = "ECC-SECG-P256K1"
// const KeySpecRSA2048 = "RSA-2048"
// const KeySpecRSA3072 = "RSA-3072"
// const KeySpecRSA4096 = "RSA-4096"

// Key represents a symmetric or asymmetric signing key
type Key struct {
	provide.Model
	VaultID     *uuid.UUID `sql:"not null;type:uuid" json:"vault_id"`
	Type        *string    `sql:"not null" json:"type"`  // symmetric or asymmetric
	Usage       *string    `sql:"not null" json:"usage"` // encrypt/decrypt or sign/verify (sign/verify only valid for asymmetric keys)
	Spec        *string    `sql:"not null" json:"spec"`
	Name        *string    `sql:"not null" json:"name"`
	Description *string    `json:"description"`
	Seed        *string    `sql:"type:bytea" json:"-"`
	PublicKey   *string    `sql:"type:bytea" json:"public_key,omitempty"`
	PrivateKey  *string    `sql:"type:bytea" json:"-"`

	Address             *string `sql:"-" json:"address,omitempty"`
	Ephemeral           *bool   `sql:"-" json:"ephemeral,omitempty"`
	EphemeralPrivateKey *string `sql:"-" json:"private_key,omitempty"`
	EphemeralSeed       *string `sql:"-" json:"seed,omitempty"`

	encrypted *bool      `sql:"-"`
	mutex     sync.Mutex `sql:"-"`
	vault     *Vault     `sql:"-"` // vault cache
}

// KeySignVerifyRequestResponse represents the API request/response parameters
// needed to sign or verify an arbitrary message
type KeySignVerifyRequestResponse struct {
	Message   *string `json:"message,omitempty"`
	Signature *string `json:"signature,omitempty"`
	Verified  *bool   `json:"verified,omitempty"`
}

// createAES256GCM creates a key using a random seed
func (k *Key) createAES256GCM() error {
	keypair, err := vaultcrypto.CreatePair(vaultcrypto.PrefixByteSeed)
	if err != nil {
		common.Log.Warningf("failed to generate Ed25519 seed; %s", err.Error())
		return err
	}

	seed, err := keypair.Seed()
	if err != nil {
		common.Log.Warningf("failed to read encoded Ed25519 seed; %s", err.Error())
		return err
	}

	k.PrivateKey = common.StringOrNil(string(seed[0:32]))

	common.Log.Debugf("created AES-256-GCM key with %d-byte seed for vault: %s", len(seed), k.VaultID)
	return nil
}

// createBabyJubJubKeypair creates a keypair on the twisted edwards babyJubJub curve
func (k *Key) createBabyJubJubKeypair() error {
	publicKey, privateKey, err := provide.TECGenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create babyJubJub keypair; %s", err.Error())
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	k.PrivateKey = common.StringOrNil(string(privateKey))
	k.PublicKey = common.StringOrNil(publicKeyHex)

	common.Log.Debugf("created babyJubJub key for vault: %s; public key: %s", k.VaultID, *k.PublicKey)
	return nil
}

// createC25519Keypair creates an c25519 keypair suitable for Diffie-Hellman key exchange
func (k *Key) createC25519Keypair() error {
	publicKey, privateKey, err := provide.C25519GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create C25519 keypair; %s", err.Error())
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	k.PrivateKey = common.StringOrNil(string(privateKey))
	k.PublicKey = common.StringOrNil(publicKeyHex)

	common.Log.Debugf("created C25519 key for vault: %s; public key: %s", k.VaultID, publicKeyHex)
	return nil
}

// createChaCha20 creates a key using a random seed
func (k *Key) createChaCha20() error {
	keypair, err := vaultcrypto.CreatePair(vaultcrypto.PrefixByteSeed)
	if err != nil {
		common.Log.Warningf("failed to generate ChaCha20 seed; %s", err.Error())
		return err
	}

	seed, err := keypair.Seed()
	if err != nil {
		common.Log.Warningf("failed to read encoded ChaCha20 seed; %s", err.Error())
		return err
	}

	_, seed, err = vaultcrypto.DecodeSeed(seed)
	if err != nil {
		common.Log.Warningf("failed to decode ChaCha20 seed; %s", err.Error())
		return err
	}
	k.Seed = common.StringOrNil(string(seed))

	common.Log.Debugf("created ChaCha20 key with %d-byte seed for vault: %s", len(seed), k.VaultID)
	return nil
}

// createDiffieHellmanSharedSecret creates a shared secret given a peer public key and signature
func (k *Key) createDiffieHellmanSharedSecret(peerPublicKey, peerSigningKey, peerSignature []byte, name, description string) error {
	k.decryptFields()
	defer k.encryptFields()

	privkey := k.Seed
	if privkey == nil {
		privkey = k.PrivateKey
	}

	if privkey == nil {
		err := errors.New("failed to calculate Diffie-Hellman shared secret; nil seed/private key")
		common.Log.Warning(err.Error())
		return err
	}

	ec25519Key, err := vaultcrypto.FromPublicKey(string(peerSigningKey))
	if err != nil {
		return fmt.Errorf("failed to compute shared secret; failed to unmarshal %d-byte Ed22519 public key: %s", len(peerPublicKey), string(peerPublicKey))
	}
	err = ec25519Key.Verify(peerPublicKey, peerSignature)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret; failed to verify %d-byte Ed22519 signature using public key: %s; %s", len(peerSignature), string(peerPublicKey), err.Error())
	}

	sharedSecret := provide.C25519ComputeSecret([]byte(*privkey), peerPublicKey)

	ecdhSecret := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
		Spec:        common.StringOrNil(KeySpecChaCha20),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Seed:        common.StringOrNil(string(sharedSecret)),
	}

	db := dbconf.DatabaseConnection()

	err = ecdhSecret.create()
	if err != nil {
		return fmt.Errorf("failed to create Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, err.Error())
	}

	if !ecdhSecret.save(db) {
		return fmt.Errorf("failed to save Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, *ecdhSecret.Errors[0].Message)
	}

	common.Log.Debugf("created Diffie-Hellman shared secret %s in vault: %s; public key: %s", ecdhSecret.ID, k.VaultID, *ecdhSecret.PublicKey)
	return nil
}

// createEd25519Keypair creates an Ed25519 keypair
func (k *Key) createEd25519Keypair() error {
	keypair, err := vaultcrypto.CreatePair(vaultcrypto.PrefixByteSeed)
	if err != nil {
		return fmt.Errorf("failed to create Ed25519 keypair; %s", err.Error())
	}

	seed, err := keypair.Seed()
	if err != nil {
		return fmt.Errorf("failed to read encoded seed of Ed25519 keypair; %s", err.Error())
	}

	publicKey, err := keypair.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to read public key of Ed25519 keypair; %s", err.Error())
	}

	k.Seed = common.StringOrNil(string(seed))
	k.PublicKey = common.StringOrNil(publicKey)

	common.Log.Debugf("created Ed25519 key with %d-byte seed for vault: %s; public key: %s", len(seed), k.VaultID, *k.PublicKey)
	return nil
}

// createSecp256k1Keypair creates a keypair on the secp256k1 curve
func (k *Key) createSecp256k1Keypair() error {
	address, privkey, err := provide.EVMGenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create secp256k1 keypair; %s", err.Error())
	}

	if k.Description == nil {
		desc := fmt.Sprintf("secp256k1 keypair; address: %s", *address)
		k.Description = common.StringOrNil(desc)
	}

	privateKey := math.PaddedBigBytes(privkey.D, privkey.Params().BitSize/8)
	publicKey := hex.EncodeToString(elliptic.Marshal(secp256k1.S256(), privkey.PublicKey.X, privkey.PublicKey.Y))

	k.PrivateKey = common.StringOrNil(string(privateKey))
	k.PublicKey = common.StringOrNil(publicKey)

	common.Log.Debugf("created secp256k1 key for vault: %s; public key: 0x%s", k.VaultID, publicKey)
	return nil
}

func (k *Key) resolveVault(db *gorm.DB) error {
	if k.VaultID == nil {
		return fmt.Errorf("unable to resolve vault without id for key: %s", k.ID)
	}

	if k.vault != nil {
		common.Log.Tracef("resolved cached pointer to vault %s within local key %s", k.vault.ID, k.ID)
		return nil
	}

	vlt := &Vault{}
	db.Where("id = ?", k.VaultID).Find(&vlt)
	if vlt == nil || vlt.ID == uuid.Nil {
		return fmt.Errorf("failed to resolve master key; no vault found for key: %s; vault id: %s", k.ID, k.VaultID)
	}
	k.vault = vlt

	return nil
}

func (k *Key) resolveMasterKey(db *gorm.DB) (*Key, error) {
	err := k.resolveVault(db)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve vault for master key resolution without vault id for key: %s", k.ID)
	}

	if k.vault == nil || k.vault.ID == uuid.Nil {
		return nil, fmt.Errorf("failed to resolve master key without vault id for key: %s", k.ID)
	}

	if k.vault.MasterKeyID != nil && k.vault.MasterKeyID.String() == k.ID.String() {
		return nil, fmt.Errorf("unable to resolve master key: %s; current key is master; vault id: %s", k.ID, k.VaultID)
	}

	masterKey, err := k.vault.resolveMasterKey(db)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve master key for key: %s; %s", k.ID, err.Error())
	}

	return masterKey, err
}

func (k *Key) setEncrypted(encrypted bool) {
	k.encrypted = &encrypted
}

func (k *Key) decryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.encrypted == nil {
		k.setEncrypted(k.ID != uuid.Nil)
	}

	if !*k.encrypted {
		return fmt.Errorf("fields already decrypted for key: %s", k.ID)
	}

	masterKey, err := k.resolveMasterKey(dbconf.DatabaseConnection())
	if err != nil {
		common.Log.Tracef("decrypting master key fields for vault: %s", k.VaultID)

		if k.Seed != nil {
			seed, err := pgputil.PGPPubDecrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := pgputil.PGPPubDecrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	} else {
		common.Log.Tracef("decrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if k.Seed != nil {
			seed, err := masterKey.Decrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := masterKey.Decrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	}

	k.setEncrypted(false)
	return nil
}

func (k *Key) encryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.encrypted == nil {
		k.setEncrypted(k.ID != uuid.Nil)
	}

	if *k.encrypted {
		return fmt.Errorf("fields already encrypted for key: %s", k.ID)
	}

	masterKey, err := k.resolveMasterKey(dbconf.DatabaseConnection())
	if err != nil {
		common.Log.Tracef("encrypting master key fields for vault: %s", k.VaultID)

		if k.Seed != nil {
			seed, err := pgputil.PGPPubEncrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := pgputil.PGPPubEncrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	} else {
		common.Log.Tracef("encrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if k.Seed != nil {
			seed, err := masterKey.Encrypt([]byte(*k.Seed))
			if err != nil {
				return err
			}
			k.Seed = common.StringOrNil(string(seed))
		}

		if k.PrivateKey != nil {
			privateKey, err := masterKey.Encrypt([]byte(*k.PrivateKey))
			if err != nil {
				return err
			}
			k.PrivateKey = common.StringOrNil(string(privateKey))
		}
	}

	k.setEncrypted(true)
	return nil
}

// Enrich the key; typically a no-op; useful for public keys which
// have a compressed representation (i.e., crypto address)
func (k *Key) Enrich() {
	if k.Spec != nil && *k.Spec == KeySpecECCSecp256k1 {
		if k.PublicKey != nil {
			pubkey, err := hex.DecodeString(*k.PublicKey)
			if err == nil {
				x, y := elliptic.Unmarshal(secp256k1.S256(), pubkey)
				if x != nil {
					publicKey := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
					addr := ethcrypto.PubkeyToAddress(*publicKey)
					k.Address = common.StringOrNil(addr.Hex())
				}
			}
		}
	}
}

// Generate key material and persist the key to the vault
func (k *Key) createPersisted(db *gorm.DB) bool {
	err := k.create()
	if err != nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	success := k.save(db)
	if success {
		k.Enrich()
	}

	return success
}

// Generate the key/keypair based on Spec type
func (k *Key) create() error {
	if !k.Validate() {
		return fmt.Errorf("failed to validate key; %s", *k.Errors[0].Message)
	}

	hasKeyMaterial := k.Seed != nil || k.PrivateKey != nil

	if k.ID != uuid.Nil && hasKeyMaterial {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("attempted to regenerate key material for key: %s", k.ID)),
		})
		return nil
	}

	if !hasKeyMaterial { // FIXME? this sucks :D
		switch *k.Spec {
		case KeySpecAES256GCM:
			err := k.createAES256GCM()
			if err != nil {
				return fmt.Errorf("failed to create AES-256-GCM key; %s", err.Error())
			}
		case KeySpecChaCha20:
			err := k.createChaCha20()
			if err != nil {
				return fmt.Errorf("failed to create ChaCha20 key; %s", err.Error())
			}
		case KeySpecECCBabyJubJub:
			err := k.createBabyJubJubKeypair()
			if err != nil {
				return fmt.Errorf("failed to create babyjubjub keypair; %s", err.Error())
			}
		case KeySpecECCC25519:
			err := k.createC25519Keypair()
			if err != nil {
				return fmt.Errorf("failed to create C25519 keypair; %s", err.Error())
			}
		case KeySpecECCEd25519:
			err := k.createEd25519Keypair()
			if err != nil {
				return fmt.Errorf("failed to create Ed22519 keypair; %s", err.Error())
			}
		case KeySpecECCSecp256k1:
			err := k.createSecp256k1Keypair()
			if err != nil {
				return fmt.Errorf("failed to create secp256k1 keypair; %s", err.Error())
			}
		}
	}

	isEphemeral := k.Ephemeral != nil && *k.Ephemeral

	if isEphemeral {
		if k.Seed != nil {
			ephemeralSeed := *k.Seed
			k.EphemeralSeed = &ephemeralSeed
		}
		if k.PrivateKey != nil {
			ephemeralPrivateKey := hex.EncodeToString([]byte(*k.PrivateKey))
			k.EphemeralPrivateKey = &ephemeralPrivateKey
		}
	}

	if k.encrypted == nil || !*k.encrypted && !isEphemeral {
		err := k.encryptFields()
		if err != nil {
			return fmt.Errorf("failed to encrypt key material; %s", err.Error())
		}
	}

	return nil
}

// Delete a key
func (k *Key) Delete(db *gorm.DB) bool {
	if k.ID == uuid.Nil {
		common.Log.Warning("attempted to delete key instance which only exists in-memory")
		return false
	}

	result := db.Delete(&k)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := len(k.Errors) == 0
	return success
}

// Create and persist a key
func (k *Key) save(db *gorm.DB) bool {
	if k.Ephemeral != nil && *k.Ephemeral {
		common.Log.Debugf("short-circuiting attempt to persist ephemeral key: %s", k.ID)
		return true
	}

	if db.NewRecord(k) {
		result := db.Create(&k)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				k.Errors = append(k.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(k) {
			success := rowsAffected > 0
			if success {
				common.Log.Debugf("created key %s (%s) in vault %s", *k.Name, k.ID.String(), k.VaultID.String())
				return success
			}
		}
	}

	return false
}

// Decrypt a ciphertext using the key according to its spec
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if k.Usage == nil || *k.Usage != KeyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key: %s; nil or invalid key usage", len(ciphertext), k.ID)
	}

	if k.Type != nil && *k.Type == KeyTypeSymmetric {
		return k.decryptSymmetric(ciphertext[12:], ciphertext[0:12])
	}

	if k.Type != nil && *k.Type == KeyTypeAsymmetric {
		return k.decryptAsymmetric(ciphertext)
	}

	return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key: %s; nil or invalid key type", len(ciphertext), k.ID)
}

// decryptAsymmetric attempts asymmetric decryption using the key;
// returns the plaintext and any error
func (k *Key) decryptAsymmetric(ciphertext []byte) ([]byte, error) {
	// k.mutex.Lock()
	// defer k.mutex.Unlock()

	k.decryptFields()
	defer k.encryptFields()

	return nil, nil
}

// decryptSymmetric attempts symmetric AES-256-GCM decryption using the key;
// returns the plaintext and any error
func (k *Key) decryptSymmetric(ciphertext, nonce []byte) ([]byte, error) {
	// k.mutex.Lock()
	// defer k.mutex.Unlock()

	// k.decryptFields()
	// defer k.encryptFields()

	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	key := []byte(*k.PrivateKey)
	var plaintext []byte

	switch *k.Spec {
	case KeySpecAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt using key: %s; %s", k.ID, err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt using key: %s; %s", k.ID, err.Error())
		}

		plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt using key: %s; %s", k.ID, err.Error())
		}
	case KeySpecChaCha20:
		// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
		nonce = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		plaintext := make([]byte, len(ciphertext))
		cipher.XORKeyStream(plaintext, ciphertext)
	}

	return plaintext, nil
}

// DeriveSymmetric derives a symmetric key from the secret stored in k.Seed
// using the given nonce and key generation context identifier; note that the nonce
// must not be reused or the secret will be exposed...
func (k *Key) DeriveSymmetric(nonce, context []byte, name, description string) (*Key, error) {
	if k.Type == nil || *k.Type != KeyTypeSymmetric {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil or invalid key type", k.ID)
	}

	if k.Usage == nil || *k.Usage != KeyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil or invalid key usage", k.ID)
	}

	if k.Spec == nil || (*k.Spec != KeySpecChaCha20) {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil or invalid key spec", k.ID)
	}

	if k.Seed == nil {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil seed", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case KeySpecChaCha20:
		key := []byte(*k.Seed)
		derivedKey, err := chacha20.HChaCha20(key, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to derive symmetric key from key: %s; %s", k.ID, err.Error())
		}

		chacha20Key := &Key{
			VaultID:     k.VaultID,
			Type:        common.StringOrNil(KeyTypeSymmetric),
			Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
			Spec:        common.StringOrNil(KeySpecChaCha20),
			Name:        common.StringOrNil(name),
			Description: common.StringOrNil(description),
			Seed:        common.StringOrNil(string(derivedKey)),
		}

		db := dbconf.DatabaseConnection()

		err = chacha20Key.create()
		if err != nil {
			return nil, fmt.Errorf("failed to create derived symmetric key from key: %s; %s", k.ID, err.Error())
		}

		if !chacha20Key.save(db) {
			return nil, fmt.Errorf("failed to save derived symmetric key from key: %s; %s", k.ID, *chacha20Key.Errors[0].Message)
		}
		return chacha20Key, nil
	}

	return nil, fmt.Errorf("failed to derive symmetric key from key: %s; %s key spec not implemented", k.ID, *k.Spec)
}

// Encrypt the given plaintext with the key, according to its spec
func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	if k.Usage == nil || *k.Usage != KeyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key usage", len(plaintext), k.ID)
	}

	if k.Type != nil && *k.Type == KeyTypeSymmetric {
		return k.encryptSymmetric(plaintext)
	}

	if k.Type != nil && *k.Type == KeyTypeAsymmetric {
		return k.encryptAsymmetric(plaintext)
	}

	return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key type", len(plaintext), k.ID)
}

// encryptAsymmetric attempts asymmetric encryption using the public/private keypair;
// returns the ciphertext any error
func (k *Key) encryptAsymmetric(plaintext []byte) ([]byte, error) {
	if k.Type == nil || *k.Type != KeyTypeAsymmetric {
		return nil, fmt.Errorf("failed to asymmetrically encrypt using key: %s; nil or invalid key type", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	return nil, nil
}

// encryptSymmetric attempts symmetric AES-256-GCM encryption using the key;
// returns the ciphertext-- with 12-byte nonce prepended-- and any error
// TODO: support optional nonce parameter & use random nonce if not provided
func (k *Key) encryptSymmetric(plaintext []byte) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered from panic during encryptSymmetric(); %s", r)
		}
	}()

	if k.Type == nil || *k.Type != KeyTypeSymmetric {
		return nil, fmt.Errorf("failed to symmetrically encrypt using key: %s; nil or invalid key type", k.ID)
	}

	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	key := []byte(*k.PrivateKey)

	var nonce []byte
	var ciphertext []byte

	switch *k.Spec {
	case KeySpecAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
		nonce = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	case KeySpecChaCha20:
		// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
		nonce = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt using key: %s; %s", k.ID, err.Error())
		}

		ciphertext := make([]byte, len(plaintext))
		cipher.XORKeyStream(ciphertext, plaintext)
	}

	return append(nonce[:], ciphertext[:]...), nil
}

// Sign the input with the private key
func (k *Key) Sign(payload []byte) ([]byte, error) {
	if k.Type == nil || *k.Type != KeyTypeAsymmetric {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != KeyUsageSignVerify {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || (*k.Spec != KeySpecECCBabyJubJub && *k.Spec != KeySpecECCEd25519 && *k.Spec != KeySpecECCSecp256k1) {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	var sig []byte
	var sigerr error

	switch *k.Spec {
	case KeySpecECCBabyJubJub:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		sig, sigerr = provide.TECSign([]byte(*k.PrivateKey), payload)
	case KeySpecECCEd25519:
		if k.Seed == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil Ed25519 seed", len(payload), k.ID)
		}
		ec25519Key, err := vaultcrypto.FromSeed([]byte(*k.Seed))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		sig, sigerr = ec25519Key.Sign(payload)
	case KeySpecECCSecp256k1:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil secp256k1 private key", len(payload), k.ID)
		}
		secp256k1Key, err := ethcrypto.ToECDSA([]byte(*k.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		r, s, err := ecdsa.Sign(rand.Reader, secp256k1Key, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		sig, err := asn1.Marshal(common.ECDSASignature{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		common.Log.Debugf("signed %d-byte payload using key: %s; r==%s; s==%s; signature: %s", len(payload), k.ID, r, s, hex.EncodeToString(sig))
		return sig, nil
	default:
		sigerr = fmt.Errorf("failed to sign %d-byte payload using key: %s; %s key spec not yet implemented", len(payload), k.ID, *k.Spec)
	}

	if sigerr != nil {
		return nil, sigerr
	}

	return sig, nil
}

// Verify the given payload against a signature using the public key
func (k *Key) Verify(payload, sig []byte) error {
	if k.Type == nil || *k.Type != KeyTypeAsymmetric {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != KeyUsageSignVerify {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || (*k.Spec != KeySpecECCBabyJubJub && *k.Spec != KeySpecECCEd25519 && *k.Spec != KeySpecECCSecp256k1) {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	if k.PublicKey == nil {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case KeySpecECCBabyJubJub:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		return provide.TECVerify([]byte(*k.PublicKey), payload, sig)
	case KeySpecECCEd25519:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		ec25519Key, err := vaultcrypto.FromPublicKey(*k.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return ec25519Key.Verify(payload, sig)
	case KeySpecECCSecp256k1:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		signature := common.ECDSASignature{}
		_, err := asn1.Unmarshal(sig, &signature)
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to unmarshal ASN1-encoded signature; %s", len(payload), k.ID, err.Error())
		}
		common.Log.Debugf("unmarshaled ASN1 signature r, s (%s, %s) for key %s", signature.R, signature.S, k.ID)
		pubkey, err := hex.DecodeString(*k.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to decode public key hex; %s", len(payload), k.ID, err.Error())
		}
		secp256k1Key, err := ethcrypto.UnmarshalPubkey([]byte(pubkey))
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to unmarshal public key; %s", len(payload), k.ID, err.Error())
		}
		if !ecdsa.Verify(secp256k1Key, payload, signature.R, signature.S) {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s", len(payload), k.ID)
		}
		return nil
	}

	return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; %s key spec not yet implemented", len(payload), k.ID, *k.Spec)
}

// Validate the key
func (k *Key) Validate() bool {
	k.Errors = make([]*provide.Error, 0)

	if k.VaultID == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("vault id required"),
		})
	}

	if k.Name == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key name required"),
		})
	}

	if k.Usage == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key usage required"),
		})
	}

	if k.Spec == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key spec required"),
		})
	}

	if k.Type == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key type required"),
		})
	} else if *k.Type != KeyTypeAsymmetric && *k.Type != KeyTypeSymmetric {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("key type must be one of %s or %s", KeyTypeAsymmetric, KeyTypeSymmetric)),
		})
	} else if *k.Type == KeyTypeSymmetric && *k.Usage != KeyUsageEncryptDecrypt {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("symmetric key requires %s usage mode", KeyUsageEncryptDecrypt)),
		})
	} else if *k.Type == KeyTypeSymmetric && *k.Usage == KeyUsageEncryptDecrypt && (k.Spec == nil || (*k.Spec != KeySpecAES256GCM && *k.Spec != KeySpecChaCha20)) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("symmetric key in %s usage mode must be %s or %s", KeyUsageEncryptDecrypt, KeySpecAES256GCM, KeySpecChaCha20)), // TODO: support KeySpecRSA2048, KeySpecRSA3072, KeySpecRSA4096
		})
	} else if *k.Type == KeyTypeAsymmetric && *k.Usage == KeyUsageSignVerify && (k.Spec == nil || (*k.Spec != KeySpecECCBabyJubJub && *k.Spec != KeySpecECCC25519 && *k.Spec != KeySpecECCEd25519 && *k.Spec != KeySpecECCSecp256k1)) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("asymmetric key in %s usage mode must be %s, %s, %s or %s", KeyUsageSignVerify, KeySpecECCBabyJubJub, KeySpecECCC25519, KeySpecECCEd25519, KeySpecECCSecp256k1)), // TODO: support KeySpecRSA2048, KeySpecRSA3072, KeySpecRSA4096
		})
	}

	return len(k.Errors) == 0
}

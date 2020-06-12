package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
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

const keyTypeAsymmetric = "asymmetric"
const keyTypeSymmetric = "symmetric"

const keyUsageEncryptDecrypt = "encrypt/decrypt"
const keyUsageSignVerify = "sign/verify"

const keySpecAES256GCM = "AES-256-GCM"
const keySpecChaCha20 = "ChaCha20"
const keySpecECCBabyJubJub = "babyJubJub"
const keySpecECCC25519 = "C25519"
const keySpecECCEd25519 = "Ed25519"
const keySpecECCSecp256k1 = "secp256k1"

// const keySpecECCSecp256r1 = "ECC-NIST-P256"
// const keySpecECCSecp2048 = "ECC-NIST-P384"
// const keySpecECCSecp521r1 = "ECC-NIST-P521"
// const keySpecECCSecpP256k1 = "ECC-SECG-P256K1"
// const keySpecRSA2048 = "RSA-2048"
// const keySpecRSA3072 = "RSA-3072"
// const keySpecRSA4096 = "RSA-4096"

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

// CreateBabyJubJubKeypair creates a keypair on the twisted edwards babyJubJub curve
func (k *Key) CreateBabyJubJubKeypair() error {
	publicKey, privateKey, err := provide.TECGenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create babyJubJub keypair; %s", err.Error())
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	k.Type = common.StringOrNil(keyTypeAsymmetric)
	k.Usage = common.StringOrNil(keyUsageSignVerify)
	k.Spec = common.StringOrNil(keySpecECCBabyJubJub)
	k.PublicKey = common.StringOrNil(publicKeyHex)
	k.PrivateKey = common.StringOrNil(string(privateKey))

	common.Log.Debugf("created babyJubJub key for vault: %s; public key: %s", k.VaultID, *k.PublicKey)
	return nil
}

// CreateDiffieHellmanSharedSecret creates a shared secret given a peer public key and signature
func (k *Key) CreateDiffieHellmanSharedSecret(peerPublicKey, peerSigningKey, peerSignature []byte, name, description string) (*Key, error) {
	k.decryptFields()
	defer k.encryptFields()

	privkey := k.Seed
	if privkey == nil {
		privkey = k.PrivateKey
	}

	if privkey == nil {
		err := errors.New("failed to calculate Diffie-Hellman shared secret; nil seed/private key")
		common.Log.Warning(err.Error())
		return nil, err
	}

	ec25519Key, err := vaultcrypto.FromPublicKey(string(peerSigningKey))
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret; failed to unmarshal %d-byte Ed22519 public key: %s", len(peerPublicKey), string(peerPublicKey))
	}
	err = ec25519Key.Verify(peerPublicKey, peerSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret; failed to verify %d-byte Ed22519 signature using public key: %s; %s", len(peerSignature), string(peerPublicKey), err.Error())
	}

	sharedSecret := provide.C25519ComputeSecret([]byte(*privkey), peerPublicKey)

	ecdhSecret := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(keyTypeSymmetric),
		Usage:       common.StringOrNil(keyUsageEncryptDecrypt),
		Spec:        common.StringOrNil(keySpecChaCha20),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Seed:        common.StringOrNil(string(sharedSecret)),
	}

	db := dbconf.DatabaseConnection()
	if !ecdhSecret.create() {
		return nil, fmt.Errorf("failed to create Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, *ecdhSecret.Errors[0].Message)
	}

	if !ecdhSecret.save(db) {
		return nil, fmt.Errorf("failed to save Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, *ecdhSecret.Errors[0].Message)
	}

	common.Log.Debugf("created Diffie-Hellman shared secret %s in vault: %s; public key: %s", ecdhSecret.ID, k.VaultID, *ecdhSecret.PublicKey)
	return ecdhSecret, nil
}

// CreateEd25519Keypair creates an Ed25519 keypair
func (k *Key) CreateEd25519Keypair() error {
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

	k.PublicKey = common.StringOrNil(publicKey)
	k.Seed = common.StringOrNil(string(seed))

	common.Log.Debugf("created Ed25519 key with %d-byte seed for vault: %s; public key: %s", len(seed), k.VaultID, *k.PublicKey)
	return nil
}

// CreateSecp256k1Keypair creates a keypair on the secp256k1 curve
func (k *Key) CreateSecp256k1Keypair() error {
	address, privkey, err := provide.EVMGenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create secp256k1 keypair; %s", err.Error())
	}

	publicKey := hex.EncodeToString(elliptic.Marshal(secp256k1.S256(), privkey.PublicKey.X, privkey.PublicKey.Y))
	privateKey := math.PaddedBigBytes(privkey.D, privkey.Params().BitSize/8)
	desc := fmt.Sprintf("%s; address: %s", *k.Description, *address)

	k.Description = common.StringOrNil(desc)
	k.PublicKey = common.StringOrNil(publicKey)
	k.PrivateKey = common.StringOrNil(string(privateKey))

	common.Log.Debugf("created secp256k1 key for vault: %s; public key: %s", k.VaultID, publicKey)
	return nil
}

// CreateC25519Keypair creates an c25519 keypair suitable for Diffie-Hellman key exchange
func (k *Key) CreateC25519Keypair() error {
	publicKey, privateKey, err := provide.C25519GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create C25519 keypair; %s", err.Error())
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	k.PublicKey = common.StringOrNil(publicKeyHex)
	k.PrivateKey = common.StringOrNil(string(privateKey))

	common.Log.Debugf("created C25519 key for vault: %s; public key: %s", k.VaultID, publicKeyHex)

	return nil
}

func (k *Key) resolveMasterKey() (*Key, error) {
	var vault *Vault
	var masterKey *Key
	var err error

	if k.VaultID == nil {
		return nil, fmt.Errorf("unable to resolve master key without vault id for key: %s", k.ID)
	}

	db := dbconf.DatabaseConnection()

	if k.vault == nil {
		vlt := &Vault{}
		db.Where("id = ?", k.VaultID).Find(&vlt)
		if vlt == nil || vlt.ID == uuid.Nil {
			return nil, fmt.Errorf("failed to resolve master key; no vault found for key: %s; vault id: %s", k.ID, k.VaultID)
		}
		k.vault = vlt
	}

	vault = k.vault

	if vault.MasterKeyID != nil && vault.MasterKeyID.String() == k.ID.String() {
		return nil, fmt.Errorf("unable to resolve master key: %s; current key is master; vault id: %s", k.ID, k.VaultID)
	}

	masterKey, err = vault.resolveMasterKey(db)
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

	masterKey, err := k.resolveMasterKey()
	if err != nil {
		common.Log.Debugf("decrypting master key fields for vault: %s", k.VaultID)

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
		common.Log.Debugf("decrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

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

	masterKey, err := k.resolveMasterKey()
	if err != nil {
		common.Log.Debugf("encrypting master key fields for vault: %s", k.VaultID)

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
		common.Log.Debugf("encrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

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
	if k.Spec != nil && *k.Spec == keySpecECCSecp256k1 {
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
	return !!k.create() && !!k.save(db) // HACK or feature? :D
}

// Generate the key/keypair based on Spec type
func (k *Key) create() bool {
	if !k.validate() {
		return false
	}

	if k.Seed != nil || k.PrivateKey != nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("attempted to regenerate key material for key: %s", k.ID)),
		})
		return false
	}

	switch *k.Spec {
	case keySpecAES256GCM:
		return false
	case keySpecChaCha20:
		return false
	case keySpecECCBabyJubJub:
		err := k.CreateBabyJubJubKeypair()
		if err != nil {
			common.Log.Warningf("failed to create babyjubjub keypair; %s", err.Error())
			return false
		}
	case keySpecECCC25519:
		err := k.CreateC25519Keypair()
		if err != nil {
			common.Log.Warningf("failed to create C25519 keypair; %s", err.Error())
			return false
		}
	case keySpecECCEd25519:
		err := k.CreateEd25519Keypair()
		if err != nil {
			common.Log.Warningf("failed to create Ed22519 keypair; %s", err.Error())
			return false
		}
	case keySpecECCSecp256k1:
		err := k.CreateSecp256k1Keypair()
		if err != nil {
			common.Log.Warningf("failed to create secp256k1 keypair; %s", err.Error())
			return false
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

	if !isEphemeral && k.encrypted == nil || !*k.encrypted {
		err := k.encryptFields()
		if err != nil {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return true
}

// Create and persist a key
func (k *Key) save(db *gorm.DB) bool {
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
	if k.Usage == nil || *k.Usage != keyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key: %s; nil or invalid key usage", len(ciphertext), k.ID)
	}

	if k.Type != nil && *k.Type == keyTypeSymmetric {
		return k.decryptSymmetric(ciphertext[12:], ciphertext[0:12])
	}

	if k.Type != nil && *k.Type == keyTypeAsymmetric {
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

// decryptSymmetric attempts symmetric AES-256 GCM decryption using the key;
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
	case keySpecAES256GCM:
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
	case keySpecChaCha20:
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

// DeriveSymmetric derives a symmetric key from the secret stored in k.PrivateKey
// using the given nonce and key generation context identifier; note that the nonce
// must not be reused or the secret will be exposed...
func (k *Key) DeriveSymmetric(nonce, context []byte, name, description string) (*Key, error) {
	if k.Type == nil && *k.Type != keyTypeSymmetric {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil or invalid key type", k.ID)
	}

	if k.Usage == nil || *k.Usage != keyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil or invalid key usage", k.ID)
	}

	if k.Spec == nil || (*k.Spec != keySpecChaCha20) {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil or invalid key spec", k.ID)
	}

	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to derive symmetric key from key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case keySpecChaCha20:
		key := []byte(*k.PrivateKey)
		derivedKey, err := chacha20.HChaCha20(key, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to derive symmetric key from key: %s; %s", k.ID, err.Error())
		}

		chacha20Key := &Key{
			VaultID:     k.VaultID,
			Type:        common.StringOrNil(keyTypeSymmetric),
			Usage:       common.StringOrNil(keyUsageEncryptDecrypt),
			Spec:        common.StringOrNil(keySpecChaCha20),
			Name:        common.StringOrNil(name),
			Description: common.StringOrNil(description),
			PrivateKey:  common.StringOrNil(string(derivedKey)),
		}

		db := dbconf.DatabaseConnection()
		if !chacha20Key.create() {
			return nil, fmt.Errorf("failed to create derived symmetric key from key: %s; %s", k.ID, *chacha20Key.Errors[0].Message)
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
	if k.Usage == nil || *k.Usage != keyUsageEncryptDecrypt {
		return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key usage", len(plaintext), k.ID)
	}

	if k.Type != nil && *k.Type == keyTypeSymmetric {
		return k.encryptSymmetric(plaintext)
	}

	if k.Type != nil && *k.Type == keyTypeAsymmetric {
		return k.encryptAsymmetric(plaintext)
	}

	return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key type", len(plaintext), k.ID)
}

// encryptAsymmetric attempts asymmetric encryption using the public/private keypair;
// returns the ciphertext any error
func (k *Key) encryptAsymmetric(plaintext []byte) ([]byte, error) {
	if k.Type == nil || *k.Type != keyTypeAsymmetric {
		return nil, fmt.Errorf("failed to asymmetrically encrypt using key: %s; nil or invalid key type", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	return nil, nil
}

// encryptSymmetric attempts symmetric AES-256 GCM encryption using the key;
// returns the ciphertext-- with 12-byte nonce prepended-- and any error
// TODO: support optional nonce parameter & use random nonce if not provided
func (k *Key) encryptSymmetric(plaintext []byte) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered from panic during encryptSymmetric(); %s", r)
		}
	}()

	if k.Type == nil || *k.Type != keyTypeSymmetric {
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
	case keySpecAES256GCM:
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
	case keySpecChaCha20:
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
	if k.Type == nil && *k.Type != keyTypeAsymmetric {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != keyUsageSignVerify {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || (*k.Spec != keySpecECCBabyJubJub && *k.Spec != keySpecECCEd25519 && *k.Spec != keySpecECCSecp256k1) {
		return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	var sig []byte
	var sigerr error

	switch *k.Spec {
	case keySpecECCBabyJubJub:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		sig, sigerr = provide.TECSign([]byte(*k.PrivateKey), payload)
	case keySpecECCEd25519:
		if k.Seed == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil Ed25519 seed", len(payload), k.ID)
		}
		ec25519Key, err := vaultcrypto.FromSeed([]byte(*k.Seed))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		sig, sigerr = ec25519Key.Sign(payload)
	case keySpecECCSecp256k1:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil secp256k1 private key", len(payload), k.ID)
		}
		secp256k1Key, err := ethcrypto.ToECDSA([]byte(*k.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return secp256k1Key.Sign(rand.Reader, payload, nil)
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
	if k.Type == nil && *k.Type != keyTypeAsymmetric {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key type", len(payload), k.ID)
	}

	if k.Usage == nil || *k.Usage != keyUsageSignVerify {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key usage", len(payload), k.ID)
	}

	if k.Spec == nil || (*k.Spec != keySpecECCBabyJubJub && *k.Spec != keySpecECCEd25519 && *k.Spec != keySpecECCSecp256k1) {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	if k.PublicKey == nil {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case keySpecECCBabyJubJub:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		return provide.TECVerify([]byte(*k.PublicKey), payload, sig)
	case keySpecECCEd25519:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		ec25519Key, err := vaultcrypto.FromPublicKey(*k.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; %s", len(payload), k.ID, err.Error())
		}
		return ec25519Key.Verify(payload, sig)
	case keySpecECCSecp256k1:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		x, y := elliptic.Unmarshal(secp256k1.S256(), []byte(*k.PublicKey))
		if x == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to unmarshal public key", len(payload), k.ID)
		}
		secp256k1Key := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
		// TODO: unmarshal sig into r and s vals
		var r *big.Int
		var s *big.Int
		if !ecdsa.Verify(secp256k1Key, payload, r, s) {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s", len(payload), k.ID)
		}
		return nil
	}

	return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; %s key spec not yet implemented", len(payload), k.ID, *k.Spec)
}

func (k *Key) validate() bool {
	k.Errors = make([]*provide.Error, 0)

	if k.Name == nil {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil("key name required"),
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
	} else if *k.Type != keyTypeAsymmetric && *k.Type != keyTypeSymmetric {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("key type must be one of %s or %s", keyTypeAsymmetric, keyTypeSymmetric)),
		})
	} else if *k.Type == keyTypeSymmetric && *k.Usage != keyUsageEncryptDecrypt {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("symmetric key requires %s usage mode", keyUsageEncryptDecrypt)),
		})
	} else if *k.Type == keyTypeSymmetric && *k.Usage == keyUsageEncryptDecrypt && (k.Spec == nil || (*k.Spec != keySpecAES256GCM && *k.Spec != keySpecChaCha20)) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("symmetric key in %s usage mode must be %s or %s", keyUsageEncryptDecrypt, keySpecAES256GCM, keySpecChaCha20)), // TODO: support keySpecRSA2048, keySpecRSA3072, keySpecRSA4096
		})
	} else if *k.Type == keyTypeAsymmetric && *k.Usage == keyUsageSignVerify && (k.Spec == nil || (*k.Spec != keySpecECCBabyJubJub && *k.Spec != keySpecECCC25519 && *k.Spec != keySpecECCEd25519 && *k.Spec != keySpecECCSecp256k1)) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("asymmetric key in %s usage mode must be %s, %s, %s or %s", keyUsageSignVerify, keySpecECCBabyJubJub, keySpecECCC25519, keySpecECCEd25519, keySpecECCSecp256k1)), // TODO: support keySpecRSA2048, keySpecRSA3072, keySpecRSA4096
		})
	}

	return len(k.Errors) == 0
}

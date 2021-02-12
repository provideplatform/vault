package vault

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/provideapp/vault/common"
	"github.com/provideapp/vault/crypto"
	provide "github.com/provideservices/provide-go/api"
	providecrypto "github.com/provideservices/provide-go/crypto"
	"golang.org/x/crypto/chacha20"
)

const defaultVaultMasterKeyName = "master0"

const maxHDIteration = 4294967295

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

// KeySpecECCBIP39 BIP39 key spec
const KeySpecECCBIP39 = "BIP39"

// KeySpecECCC25519 C25519 key spec
const KeySpecECCC25519 = "C25519"

// KeySpecECCEd25519 Ed25519 key spec
const KeySpecECCEd25519 = "Ed25519"

// KeySpecECCSecp256k1 secp256k1 key spec
const KeySpecECCSecp256k1 = "secp256k1"

// NonceSizeSymmetric chacha20 & aes256 encrypt/decrypt nonce size
const NonceSizeSymmetric = 12

// const KeySpecECCSecp256r1 = "ECC-NIST-P256"
// const KeySpecECCSecp2048 = "ECC-NIST-P384"
// const KeySpecECCSecp521r1 = "ECC-NIST-P521"
// const KeySpecECCSecpP256k1 = "ECC-SECG-P256K1"

// KeySpecRSA2048 rsa 2048 key spec
const KeySpecRSA2048 = "RSA-2048"

// KeyBits2048 is the bit length for 2048-bit keys
const KeyBits2048 = 2048

// KeyBits3072 is the bit length for 3072-bit keys
const KeyBits3072 = 3072

// KeyBits4096 is the bit length for 4096-bit keys
const KeyBits4096 = 4096

// KeySpecRSA3072 rsa 3072 key spec
const KeySpecRSA3072 = "RSA-3072"

// KeySpecRSA4096 rsa 4096 key spec
const KeySpecRSA4096 = "RSA-4096"

// Key represents a symmetric or asymmetric signing key
type Key struct {
	provide.Model
	VaultID                 *uuid.UUID `sql:"not null;type:uuid" json:"vault_id"`
	Type                    *string    `sql:"not null" json:"type"`  // symmetric or asymmetric
	Usage                   *string    `sql:"not null" json:"usage"` //TODO: purpose to change...
	Spec                    *string    `sql:"not null" json:"spec"`
	Name                    *string    `sql:"not null" json:"name"`
	Description             *string    `json:"description"`
	Seed                    *[]byte    `sql:"type:bytea" json:"-"`
	PublicKey               *[]byte    `sql:"type:bytea" json:"-"`
	PrivateKey              *[]byte    `sql:"type:bytea" json:"-"`
	IterativeDerivationPath *string    `gorm:"column:iterative_hd_derivation_path" json:"-"`
	Mnemonic                *string    `sql:"-" json:"mnemonic,omitempty"`

	Address             *string `sql:"-" json:"address,omitempty"`
	Ephemeral           *bool   `sql:"-" json:"ephemeral,omitempty"`
	EphemeralPrivateKey *string `sql:"-" json:"private_key,omitempty"`
	EphemeralSeed       *string `sql:"-" json:"seed,omitempty"`
	PublicKeyHex        *string `sql:"-" json:"public_key,omitempty"`
	DerivationPath      *string `sql:"-" json:"hd_derivation_path,omitempty"`
	// HardenedDerivationPath      *string `json:"hardened_hd_derivation_path,omitempty"` <-- may be useful to store this, i.e., m/44'/60'/0'

	encrypted *bool      `sql:"-"`
	mutex     sync.Mutex `sql:"-"`
	vault     *Vault     `sql:"-"` // vault cache
}

// KeyEncryptDecryptRequestResponse contains the data to be encrypted/decrypted
// data is submitted and received as a string
// encrypted data is returned hex encoded
// decrypted data is returned as received
// nonce is optional and a random nonce will be created if not present
// note that nonces must not be reused and using 2^32 random nonces is not secure
type KeyEncryptDecryptRequestResponse struct {
	Data  *string `json:"data,omitempty"`
	Nonce *string `json:"nonce,omitempty"` //optional nonce parameter
}

// KeyDeriveRequest contains the details for the derivation of a new key,
// provided the parent key is supports derivation; currently supports ChaCha20 or BIP30 keys
type KeyDeriveRequest struct {
	Nonce       *int    `json:"nonce,omitempty"`
	Context     *string `json:"context,omitempty"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Path        *string `json:"hd_derivation_path,omitempty"`
}

// SigningOptions contains the options for the signing algorithm
// such as rsa algorithm (RS256, RS384, RS512, PS256, PS384, PS512)
// hd wallet coin type (BTC, ETH)
// hd wallet derivation path or iteration (deterministic account index)
// and likely other stuff in the future...
type SigningOptions struct {
	Algorithm *string          `json:"algorithm,omitempty"`
	HDWallet  *crypto.HDWallet `json:"hdwallet,omitempty"`
}

// KeySignVerifyRequestResponse represents the API request/response parameters
// needed to sign or verify an arbitrary message
type KeySignVerifyRequestResponse struct {
	Message        *string         `json:"message,omitempty"`
	Options        *SigningOptions `json:"options,omitempty"`
	Signature      *string         `json:"signature,omitempty"`
	Verified       *bool           `json:"verified,omitempty"`
	Address        *string         `json:"address,omitempty"`
	DerivationPath *string         `json:"hd_derivation_path,omitempty"`
}

// DetachedVerifyRequestResponse represents the API request/response parameters
// needed to verify a provided signature created outside of vault
type DetachedVerifyRequestResponse struct {
	Spec         *string         `json:"spec,omitempty"`
	Message      *string         `json:"message,omitempty"`
	Signature    *string         `json:"signature,omitempty"`
	Options      *SigningOptions `json:"options,omitempty"`
	Verified     *bool           `json:"verified,omitempty"`
	PublicKeyHex *string         `json:"pubkeyhex,omitempty"`
}

// createAES256GCM creates a key using a random seed
func (k *Key) createAES256GCM() error {
	privatekey, err := crypto.CreateAES256GCMSeed()
	if err != nil {
		return err
	}

	k.PrivateKey = &privatekey
	k.Type = common.StringOrNil(KeyTypeSymmetric)
	k.Spec = common.StringOrNil(KeySpecAES256GCM)

	common.Log.Debugf("created AES256GCM key for vault: %s;", k.VaultID)
	return nil
}

// createBabyJubJubKeypair creates a keypair on the twisted edwards babyJubJub curve
func (k *Key) createBabyJubJubKeypair() error {
	publicKey, privateKey, err := providecrypto.TECGenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create babyJubJub keypair; %s", err.Error())
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	k.PrivateKey = &privateKey
	k.PublicKey = &publicKey
	k.Type = common.StringOrNil(KeyTypeAsymmetric)
	k.Spec = common.StringOrNil(KeySpecECCBabyJubJub)

	common.Log.Debugf("created babyJubJub key for vault: %s; public key: %s", k.VaultID, publicKeyHex)
	return nil
}

// createC25519Keypair creates an c25519 keypair suitable for Diffie-Hellman key exchange
func (k *Key) createC25519Keypair() error {
	c25519KeyPair, err := crypto.CreateC25519KeyPair()
	if err != nil {
		return crypto.ErrCannotGenerateKey
	}

	k.PrivateKey = c25519KeyPair.PrivateKey
	k.PublicKey = c25519KeyPair.PublicKey
	k.Type = common.StringOrNil(KeyTypeAsymmetric)
	k.Spec = common.StringOrNil(KeySpecECCC25519)

	common.Log.Debugf("created C25519 key for vault: %s; public key: %s", k.VaultID, hex.EncodeToString(*c25519KeyPair.PublicKey))
	return nil
}

// createChaCha20 creates a key using a random seed
func (k *Key) createChaCha20() error {
	seed, err := crypto.CreateChaChaSeed()
	if err != nil {
		return crypto.ErrCannotGenerateKey
	}

	k.Seed = &seed
	k.Type = common.StringOrNil(KeyTypeSymmetric)
	k.Spec = common.StringOrNil(KeySpecChaCha20)

	common.Log.Debugf("created chacha20 key for vault: %s;", k.VaultID)
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

	ec25519Key := ed25519.PublicKey(peerSigningKey)
	if ec25519Key == nil {
		return nil, fmt.Errorf("failed to compute shared secret; failed to unmarshal %d-byte Ed22519 public key: %s", len(peerPublicKey), string(peerPublicKey))
	}

	err := crypto.Ed25519Verify(ec25519Key, peerPublicKey, peerSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret; failed to verify %d-byte Ed22519 signature using public key: %s; %s", len(peerSignature), string(peerPublicKey), err.Error())
	}

	sharedSecret := providecrypto.C25519ComputeSecret([]byte(*privkey), peerPublicKey)

	ecdhSecret := &Key{
		VaultID:     k.VaultID,
		Type:        common.StringOrNil(KeyTypeSymmetric),
		Usage:       common.StringOrNil(KeyUsageEncryptDecrypt),
		Spec:        common.StringOrNil(KeySpecChaCha20),
		Name:        common.StringOrNil(name),
		Description: common.StringOrNil(description),
		Seed:        &sharedSecret,
	}

	db := dbconf.DatabaseConnection()

	err = ecdhSecret.create()
	if err != nil {
		return nil, fmt.Errorf("failed to create Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, err.Error())
	}

	if !ecdhSecret.save(db) {
		return nil, fmt.Errorf("failed to save Diffie-Hellman shared secret in vault: %s; %s", k.VaultID, *ecdhSecret.Errors[0].Message)
	}

	common.Log.Debugf("created Diffie-Hellman shared secret %s in vault: %s", ecdhSecret.ID, k.VaultID)
	return ecdhSecret, nil
}

// createEd25519Keypair creates an Ed25519 keypair
func (k *Key) createEd25519Keypair() error {
	publicKey, privateKey, err := crypto.CreateEd25519KeyPair()
	if err != nil {
		return crypto.ErrCannotGenerateKey
	}

	publicKeyBytes := []byte(publicKey)

	seed := privateKey.Seed()
	k.Seed = &seed
	k.PublicKey = &publicKeyBytes
	k.Type = common.StringOrNil(KeyTypeAsymmetric)
	k.Spec = common.StringOrNil(KeySpecECCEd25519)

	common.Log.Debugf("created Ed25519 key with %d-byte seed for vault: %s; public key: %s", len(seed), k.VaultID, hex.EncodeToString(*k.PublicKey))
	return nil
}

// createSecp256k1Keypair creates a keypair on the secp256k1 curve
func (k *Key) createSecp256k1Keypair() error {
	secp256k1KeyPair, err := crypto.CreateSecp256k1KeyPair()
	if err != nil {
		return crypto.ErrCannotGenerateKey
	}

	k.PrivateKey = secp256k1KeyPair.PrivateKey
	k.PublicKey = secp256k1KeyPair.PublicKey
	k.Type = common.StringOrNil(KeyTypeAsymmetric)
	k.Spec = common.StringOrNil(KeySpecECCSecp256k1)

	if k.Description == nil {
		desc := fmt.Sprintf("secp256k1 keypair; address: %s", *secp256k1KeyPair.Address)
		k.Description = common.StringOrNil(desc)
	}

	common.Log.Debugf("created secp256k1 key for vault: %s; public key: 0x%s", k.VaultID, *k.PublicKey)
	return nil
}

func (k *Key) createHDWallet() error {
	hdwllt, err := crypto.CreateHDWalletWithEntropy(crypto.DefaultHDWalletSeedEntropy)
	if err != nil {
		return fmt.Errorf("unable to create HD wallet; %s", err.Error())
	}

	k.Seed = hdwllt.Seed
	k.Type = common.StringOrNil(KeyTypeAsymmetric)
	k.IterativeDerivationPath = common.StringOrNil(crypto.DefaultHDDerivationPath().String())
	k.PublicKey = hdwllt.PublicKey
	k.PublicKeyHex = common.StringOrNil(string(*hdwllt.PublicKey))
	k.Spec = common.StringOrNil(KeySpecECCBIP39)

	if k.Description == nil {
		desc := fmt.Sprint("BIP39 HD Wallet")
		k.Description = common.StringOrNil(desc)
	}

	common.Log.Debugf("created HD wallet for vault: %s;", k.VaultID)
	return nil
}

func (k *Key) createHDWalletFromSeedPhrase(mnemonic []byte) error {
	hdwllt, err := crypto.CreateHDWalletFromSeedPhrase(string(mnemonic))
	if err != nil {
		return fmt.Errorf("unable to create HD wallet; %s", err.Error())
	}

	k.Seed = hdwllt.Seed
	k.Type = common.StringOrNil(KeyTypeAsymmetric)
	k.IterativeDerivationPath = common.StringOrNil(crypto.DefaultHDDerivationPath().String())
	k.PublicKey = hdwllt.PublicKey
	k.PublicKeyHex = common.StringOrNil(string(*hdwllt.PublicKey))
	k.Spec = common.StringOrNil(KeySpecECCBIP39)

	if k.Description == nil {
		desc := fmt.Sprint("BIP39 HD Wallet")
		k.Description = common.StringOrNil(desc)
	}

	common.Log.Debugf("created HD wallet for vault: %s;", k.VaultID)
	return nil
}

// createRSAKeypair creates a keypair using RSA(-bitsize bits)
func (k *Key) createRSAKeypair(bitsize int) error {
	rsaKeyPair, err := crypto.CreateRSAKeyPair(bitsize)
	if err != nil {
		return crypto.ErrCannotGenerateKey
	}

	k.PrivateKey = rsaKeyPair.PrivateKey
	k.PublicKey = rsaKeyPair.PublicKey
	k.Type = common.StringOrNil(KeyTypeAsymmetric)

	switch bitsize {
	case 2048:
		k.Spec = common.StringOrNil(KeySpecRSA2048)
	case 3072:
		k.Spec = common.StringOrNil(KeySpecRSA3072)
	case 4096:
		k.Spec = common.StringOrNil(KeySpecRSA4096)
	}

	common.Log.Debugf("created rsa%d key for vault: %s; public key: 0x%s", bitsize, k.VaultID, *k.PublicKey)
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

	if unsealerKey == nil {
		return fmt.Errorf("vault is sealed")
	}

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
			// unseal the data with the unsealer key
			k.Seed, err = unseal(k.Seed)
			if err != nil {
				return err
			}
		}

		if k.PrivateKey != nil {
			// unseal the data with the unsealer key
			k.PrivateKey, err = unseal(k.PrivateKey)
			if err != nil {
				return err
			}
		}
	} else {
		common.Log.Tracef("decrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if k.Seed != nil {
			seed, err := masterKey.Decrypt(*k.Seed)
			if err != nil {
				return err
			}
			k.Seed = &seed
		}

		if k.PrivateKey != nil {
			privateKey, err := masterKey.Decrypt(*k.PrivateKey)
			if err != nil {
				return err
			}
			k.PrivateKey = &privateKey
		}
	}

	k.setEncrypted(false)
	return nil
}

func (k *Key) encryptFields() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if unsealerKey == nil {
		return fmt.Errorf("vault is sealed")
	}

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
			// seal the data with the unsealer key
			k.Seed, err = seal(k.Seed)
			if err != nil {
				return err
			}
		}

		if k.PrivateKey != nil {
			// seal the data with the unsealer key
			k.PrivateKey, err = seal(k.PrivateKey)
			if err != nil {
				return err
			}
		}
	} else {
		common.Log.Tracef("encrypting key fields with master key %s for vault: %s", masterKey.ID, k.VaultID)

		masterKey.decryptFields()
		defer masterKey.encryptFields()

		if k.Seed != nil {
			seed, err := masterKey.Encrypt(*k.Seed, nil)
			if err != nil {
				return err
			}
			k.Seed = &seed
		}

		if k.PrivateKey != nil {
			privateKey, err := masterKey.Encrypt(*k.PrivateKey, nil)
			if err != nil {
				return err
			}
			k.PrivateKey = &privateKey
		}
	}

	k.setEncrypted(true)
	return nil
}

// Enrich the key; typically a no-op; useful for public keys which
// have a compressed representation (i.e., crypto address)
func (k *Key) Enrich() {
	if k.PublicKey != nil {
		if k.Spec != nil && *k.Spec == KeySpecECCSecp256k1 {
			pubkey := *k.PublicKey
			x, y := elliptic.Unmarshal(secp256k1.S256(), pubkey)
			if x != nil {
				publicKey := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
				addr := ethcrypto.PubkeyToAddress(*publicKey)
				k.Address = common.StringOrNil(addr.Hex())
			}
		}

		if k.Spec != nil && *k.Spec == KeySpecECCBIP39 {
			k.PublicKeyHex = common.StringOrNil(string(*k.PublicKey))
		} else {
			k.PublicKeyHex = common.StringOrNil(fmt.Sprintf("0x%s", hex.EncodeToString(*k.PublicKey)))
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

	hasKeyMaterial := k.Seed != nil || k.PrivateKey != nil || k.Mnemonic != nil

	if strings.EqualFold(*k.Spec, KeySpecECCBIP39) && hasKeyMaterial {

		// first check that we only have the mnemonic phrase, not a seed or private key
		if k.Mnemonic == nil {
			return fmt.Errorf("mnemonic required to create BIP39 key from existing seed phrase")
		}

		// attempt to create a hd wallet from the provided mnemonic
		err := k.createHDWalletFromSeedPhrase([]byte(*k.Mnemonic))
		if err != nil {
			return fmt.Errorf("failed to create hd wallet; %s", err.Error())
		}
	}

	// if we have a provided seed/private key and it's not a BIP39 key,
	// then append an error
	if k.ID != uuid.Nil && hasKeyMaterial && !strings.EqualFold(*k.Spec, KeySpecECCBIP39) {
		k.Errors = append(k.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("attempted to regenerate key material for key: %s", k.ID)),
		})
		return nil
	}

	if !hasKeyMaterial {
		switch strings.ToUpper(*k.Spec) {
		case strings.ToUpper(KeySpecAES256GCM):
			err := k.createAES256GCM()
			if err != nil {
				return fmt.Errorf("failed to create AES-256-GCM key; %s", err.Error())
			}
		case strings.ToUpper(KeySpecChaCha20):
			err := k.createChaCha20()
			if err != nil {
				return fmt.Errorf("failed to create ChaCha20 key; %s", err.Error())
			}
		case strings.ToUpper(KeySpecECCBabyJubJub):
			err := k.createBabyJubJubKeypair()
			if err != nil {
				return fmt.Errorf("failed to create babyjubjub keypair; %s", err.Error())
			}
		case strings.ToUpper(KeySpecECCC25519):
			err := k.createC25519Keypair()
			if err != nil {
				return fmt.Errorf("failed to create C25519 keypair; %s", err.Error())
			}
		case strings.ToUpper(KeySpecECCEd25519):
			err := k.createEd25519Keypair()
			if err != nil {
				return fmt.Errorf("failed to create Ed22519 keypair; %s", err.Error())
			}
		case strings.ToUpper(KeySpecECCBIP39):
			err := k.createHDWallet()
			if err != nil {
				return fmt.Errorf("failed to create hd wallet; %s", err.Error())
			}
		case strings.ToUpper(KeySpecECCSecp256k1):
			err := k.createSecp256k1Keypair()
			if err != nil {
				return fmt.Errorf("failed to create secp256k1 keypair; %s", err.Error())
			}
		case strings.ToUpper(KeySpecRSA4096):
			err := k.createRSAKeypair(KeyBits4096)
			if err != nil {
				return fmt.Errorf("failed to create rsa keypair; %s", err.Error())
			}
		case strings.ToUpper(KeySpecRSA3072):
			err := k.createRSAKeypair(KeyBits3072)
			if err != nil {
				return fmt.Errorf("failed to create rsa keypair; %s", err.Error())
			}
		case strings.ToUpper(KeySpecRSA2048):
			err := k.createRSAKeypair(KeyBits2048)
			if err != nil {
				return fmt.Errorf("failed to create rsa keypair; %s", err.Error())
			}
		}
	}

	isEphemeral := k.Ephemeral != nil && *k.Ephemeral

	if isEphemeral {
		if k.Seed != nil {
			ephemeralSeed := string(*k.Seed)

			// hex encode the seed if it's not a BIP39 seed
			if *k.Spec != KeySpecECCBIP39 {
				SeedHex := hex.EncodeToString(*k.Seed)
				ephemeralSeed = fmt.Sprintf("0x%s", SeedHex)
			}

			k.EphemeralSeed = &ephemeralSeed
		}

		if k.PrivateKey != nil {
			privateKeyHex := hex.EncodeToString(*k.PrivateKey)
			ephemeralPrivateKey := fmt.Sprintf("0x%s", privateKeyHex)
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

// update the hd wallet iterative derivation path; only supports a single coin
// type at this time, i.e., the coin type used when the master key is initialized
func (k *Key) updateIterativeDerivationPath(db *gorm.DB) error {
	if k.Ephemeral != nil && *k.Ephemeral {
		common.Log.Debugf("short-circuiting attempt to persist ephemeral key: %s", k.ID)
		return fmt.Errorf("cannot update iteration for ephemeral key")
	}

	derivationPath, err := hdwallet.ParseDerivationPath(*k.IterativeDerivationPath)
	if err != nil {
		return fmt.Errorf("failed to update iterative hd derivation path on key: %s; failed path: %s", k.ID, *k.IterativeDerivationPath)
	}

	account := derivationPath[2] - 0x80000000
	index := derivationPath[len(derivationPath)-1]

	// if we have reached the uint32 maximum, we cannot generate any more keys
	if index == maxHDIteration {
		common.Log.Debugf("maximum index %d reached - incrementing account", index)
		account = account + 1
		index = 0
	} else {
		index = index + 1
	}

	k.IterativeDerivationPath = common.StringOrNil(fmt.Sprintf("m/%d'/%d'/%d'/%d/%d",
		derivationPath[0]-0x80000000,
		derivationPath[1]-0x80000000,
		account,
		derivationPath[3],
		index,
	))

	result := db.Save(&k)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			k.Errors = append(k.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	rowsAffected := result.RowsAffected
	if rowsAffected == 0 {
		return fmt.Errorf("invalid key and/or path - no iterative derivation path update possible")
	}

	return nil
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
	if k.Type != nil && *k.Type == KeyTypeSymmetric {
		return k.decryptSymmetric(ciphertext[NonceSizeSymmetric:], ciphertext[0:NonceSizeSymmetric])
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

	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	var plaintext []byte
	var err error

	switch *k.Spec {
	case KeySpecRSA4096:
		rsa4096 := crypto.RSAKeyPair{}
		rsa4096.PrivateKey = k.PrivateKey
		plaintext, err = rsa4096.Decrypt(ciphertext)
		if err != nil {
			return nil, crypto.ErrCannotDecrypt
		}

	case KeySpecRSA3072:
		rsa3072 := crypto.RSAKeyPair{}
		rsa3072.PrivateKey = k.PrivateKey
		plaintext, err = rsa3072.Decrypt(ciphertext)
		if err != nil {
			return nil, crypto.ErrCannotDecrypt
		}

	case KeySpecRSA2048:
		rsa2048 := crypto.RSAKeyPair{}
		rsa2048.PrivateKey = k.PrivateKey
		plaintext, err = rsa2048.Decrypt(ciphertext)
		if err != nil {
			return nil, crypto.ErrCannotDecrypt
		}
	}
	return plaintext, nil
}

// decryptSymmetric attempts symmetric decryption,
// returns the plaintext and any error
func (k *Key) decryptSymmetric(ciphertext, nonce []byte) ([]byte, error) {
	// k.mutex.Lock()
	// defer k.mutex.Unlock()
	//TODO validate mutex

	if *k.Spec == KeySpecAES256GCM && k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; nil private key", k.ID)
	}

	if *k.Spec == KeySpecChaCha20 && k.Seed == nil {
		return nil, fmt.Errorf("failed to decrypt using key: %s; nil seed", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	var plaintext []byte

	switch *k.Spec {
	case KeySpecAES256GCM:
		aes256 := crypto.AES256GCM{}
		aes256.PrivateKey = k.PrivateKey

		var err error
		plaintext, err = aes256.Decrypt(ciphertext, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key %s. Error: %s", len(plaintext), k.ID, err.Error())
		}

	case KeySpecChaCha20:
		chacha := crypto.ChaCha{}
		chacha.Seed = k.Seed

		var err error
		plaintext, err = chacha.Decrypt(ciphertext, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %d-byte ciphertext using key %s. Error: %s", len(plaintext), k.ID, err.Error())
		}
	}

	return plaintext, nil
}

// deriveSecp256k1KeyFromHDWallet derives a secp256k1 keypair from the underlying
// master key, assuming the key implements the BIP39 spec, using the given derivation path
func (k *Key) deriveSecp256k1KeyFromHDWallet(path accounts.DerivationPath) (*crypto.Secp256k1, error) {
	if k.Spec == nil || *k.Spec != KeySpecECCBIP39 {
		return nil, fmt.Errorf("failed to derive HD wallet from key: %s; nil or invalid key spec", k.ID)
	}

	if k.Seed == nil {
		return nil, fmt.Errorf("failed to derive HD wallet from key: %s; nil seed", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch path[1] - 0x80000000 {
	case crypto.HDWalletCoinCodeEthereum:
		hdwllt := &crypto.HDWallet{
			Seed: k.Seed,
		}

		derivedKey, err := hdwllt.DeriveKey(path)
		if err != nil {
			return nil, fmt.Errorf("could not derive HD wallet key (derivation path: %s) using HD wallet master key %s", path.String(), k.ID)
		}

		return derivedKey, nil

	case crypto.HDWalletCoinCodeBitcoin:
		return nil, fmt.Errorf("bitcoin hd key derivation is not yet supported")

	default:
		return nil, fmt.Errorf("unsupported coin type in HD derivation path: %s", path.String())
	}
}

// DeriveSymmetric derives a symmetric key from the secret stored in k.Seed
// using the given nonce and key generation context identifier; note that the nonce
// must not be reused or the secret will be exposed...
func (k *Key) DeriveSymmetric(nonce, context []byte, name, description string) (*Key, error) {
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
			Seed:        &derivedKey,
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
// nonce is optional and a random nonce will be generated if nil
// never use more than 2^32 random nonces with a given key because of the risk of a repeat.
func (k *Key) Encrypt(plaintext []byte, nonce []byte) ([]byte, error) {
	if k.Type != nil && *k.Type == KeyTypeSymmetric {
		return k.encryptSymmetric(plaintext, nonce)
	}

	if k.Type != nil && *k.Type == KeyTypeAsymmetric {
		return k.encryptAsymmetric(plaintext)
	}

	return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key: %s; nil or invalid key type", len(plaintext), k.ID)
}

// encryptAsymmetric attempts asymmetric encryption using the public key;
// returns the ciphertext any error
func (k *Key) encryptAsymmetric(plaintext []byte) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered from panic during encryptAsymmetric(); %s", r)
		}
	}()

	k.decryptFields()
	defer k.encryptFields()

	var ciphertext []byte
	var err error

	switch *k.Spec {
	case KeySpecRSA4096:
		rsa4096key := crypto.RSAKeyPair{
			PublicKey: k.PublicKey,
		}
		ciphertext, err = rsa4096key.Encrypt(plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt. Error: %s", err.Error())
		}

	case KeySpecRSA3072:
		rsa3072key := crypto.RSAKeyPair{
			PublicKey: k.PublicKey,
		}
		ciphertext, err = rsa3072key.Encrypt(plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt. Error: %s", err.Error())
		}

	case KeySpecRSA2048:
		rsa2048key := crypto.RSAKeyPair{
			PublicKey: k.PublicKey,
		}
		ciphertext, err = rsa2048key.Encrypt(plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt. Error: %s", err.Error())
		}
	}
	return ciphertext, nil
}

// encryptSymmetric attempts symmetric AES-256-GCM encryption using the key;
// returns the ciphertext-- with 12-byte nonce prepended-- and any error
// nonce is optional and if nil is passed in, a random nonce is created
func (k *Key) encryptSymmetric(plaintext []byte, nonce []byte) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered from panic during encryptSymmetric(); %s", r)
		}
	}()

	if *k.Spec == KeySpecChaCha20 && k.Seed == nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; nil seed", k.ID)
	}

	if *k.Spec == KeySpecAES256GCM && k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to encrypt using key: %s; nil private key", k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	var ciphertext []byte

	switch *k.Spec {
	case KeySpecAES256GCM:
		aes256 := crypto.AES256GCM{
			PrivateKey: k.PrivateKey,
		}

		var err error
		ciphertext, err = aes256.Encrypt(plaintext, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key %s. Error: %s", len(plaintext), k.ID, err.Error())
		}

	case KeySpecChaCha20:
		chacha := crypto.ChaCha{
			Seed: k.Seed,
		}

		var err error
		ciphertext, err = chacha.Encrypt(plaintext, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt %d-byte plaintext using key %s. Error: %s", len(plaintext), k.ID, err.Error())
		}
	}

	return ciphertext, nil
}

// Sign the input with the private key
func (k *Key) Sign(payload []byte, opts *SigningOptions) ([]byte, error) {
	if k.Spec == nil || (*k.Spec != KeySpecECCBabyJubJub && *k.Spec != KeySpecECCEd25519 && *k.Spec != KeySpecECCSecp256k1 && *k.Spec != KeySpecRSA4096 && *k.Spec != KeySpecRSA3072 && *k.Spec != KeySpecRSA2048 && *k.Spec != KeySpecECCBIP39) {
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
		sig, sigerr = providecrypto.TECSign([]byte(*k.PrivateKey), payload)

	case KeySpecECCBIP39:
		if k.Seed == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using hd wallet key: %s; nil seed phrase", len(payload), k.ID)
		}

		var path *accounts.DerivationPath
		var err error

		if opts != nil {
			path, err = opts.validateHDWalletOpts()
			if err != nil {
				return nil, err
			}
		} else if k.IterativeDerivationPath != nil {
			_path, _ := hdwallet.ParseDerivationPath(*k.IterativeDerivationPath)
			path = &_path
		} else {
			path = crypto.DefaultHDDerivationPath()
		}

		// derive the secp256k1 key using the keyindex
		secp256k1Derived, err := k.deriveSecp256k1KeyFromHDWallet(*path)
		if err != nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; error generating derived key %s", len(payload), k.ID, err.Error())
		}

		k.Address = secp256k1Derived.Address
		k.DerivationPath = secp256k1Derived.DerivationPath

		k.mutex.Lock()
		defer k.mutex.Unlock()

		sig, sigerr = secp256k1Derived.Sign(payload)
		if sigerr == nil && opts == nil {
			// update the iterative derivation path if no wallet options were set
			err := k.updateIterativeDerivationPath(dbconf.DatabaseConnection())
			if err != nil {
				return nil, fmt.Errorf("error updating wallet iteration in database for key ID %s with error %s, key errors %+v", k.ID, err.Error(), k.Errors)
			}
		}

	case KeySpecECCEd25519:
		if k.Seed == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil Ed25519 seed", len(payload), k.ID)
		}
		ec25519Key := crypto.FromSeed(*k.Seed)
		if ec25519Key == nil {
			return nil, fmt.Errorf("failed to create public key from seed using key: %s", k.ID)
		}
		sig = crypto.Ed25519Sign(ec25519Key, payload)

	case KeySpecECCSecp256k1:
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		secp256k1 := crypto.Secp256k1{}
		secp256k1.PrivateKey = k.PrivateKey
		sig, sigerr = secp256k1.Sign(payload)

	case KeySpecRSA4096:
		if opts == nil || opts.Algorithm == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using hd wallet key: %s; nil signing options", len(payload), k.ID)
		}
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		rsa4096 := crypto.RSAKeyPair{}
		rsa4096.PrivateKey = k.PrivateKey
		sig, sigerr = rsa4096.Sign(payload, *opts.Algorithm)

	case KeySpecRSA3072:
		if opts == nil || opts.Algorithm == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using hd wallet key: %s; nil signing options", len(payload), k.ID)
		}
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		rsa3072 := crypto.RSAKeyPair{}
		rsa3072.PrivateKey = k.PrivateKey
		sig, sigerr = rsa3072.Sign(payload, *opts.Algorithm)

	case KeySpecRSA2048:
		if opts == nil || opts.Algorithm == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using hd wallet key: %s; nil signing options", len(payload), k.ID)
		}
		if k.PrivateKey == nil {
			return nil, fmt.Errorf("failed to sign %d-byte payload using key: %s; nil private key", len(payload), k.ID)
		}
		rsa2048 := crypto.RSAKeyPair{}
		rsa2048.PrivateKey = k.PrivateKey
		sig, sigerr = rsa2048.Sign(payload, *opts.Algorithm)

	default:
		sigerr = fmt.Errorf("failed to sign %d-byte payload using key: %s; %s key spec not yet implemented", len(payload), k.ID, *k.Spec)
	}

	if sigerr != nil {
		return nil, sigerr
	}

	return sig, nil
}

// Verify the given payload against a signature using the public key
func (k *Key) Verify(payload, sig []byte, opts *SigningOptions) error {
	if k.Spec == nil || (*k.Spec != KeySpecECCBabyJubJub && *k.Spec != KeySpecECCEd25519 && *k.Spec != KeySpecECCSecp256k1 && *k.Spec != KeySpecRSA4096 && *k.Spec != KeySpecRSA3072 && *k.Spec != KeySpecRSA2048 && *k.Spec != KeySpecECCBIP39) {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil or invalid key spec", len(payload), k.ID)
	}

	if *k.Type == KeyTypeAsymmetric && *k.Spec == KeySpecECCBIP39 && k.Seed == nil {
		return fmt.Errorf("failed to verify signature of %d-byte payload using derived key: %s; no seed phrase available", len(payload), k.ID)
	}

	if *k.Type == KeyTypeAsymmetric && k.PublicKey == nil {
		return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
	}

	k.decryptFields()
	defer k.encryptFields()

	switch *k.Spec {
	case KeySpecECCBabyJubJub:
		decodedPubKey := *k.PublicKey
		return providecrypto.TECVerify(decodedPubKey, payload, sig)

	case KeySpecECCEd25519:
		decodedPubKey := *k.PublicKey
		return crypto.Ed25519Verify(decodedPubKey, payload, sig)

	case KeySpecECCBIP39:
		var path *accounts.DerivationPath
		var err error

		if opts != nil {
			path, err = opts.validateHDWalletOpts()
			if err != nil {
				return err
			}
		} else if k.IterativeDerivationPath != nil {
			_path, _ := hdwallet.ParseDerivationPath(*k.IterativeDerivationPath)
			path = &_path
		} else {
			path = crypto.DefaultHDDerivationPath()
		}

		// derive the secp256k1 key for verification
		secp256k1Derived, err := k.deriveSecp256k1KeyFromHDWallet(*path)
		if err != nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; failed to derive hd wallet key; %s", len(payload), k.ID, err.Error())
		}
		return secp256k1Derived.Verify(payload, sig)

	case KeySpecECCSecp256k1:
		if k.PublicKey == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; nil public key", len(payload), k.ID)
		}
		secp256k1 := crypto.Secp256k1{
			PublicKey: k.PublicKey,
		}
		return secp256k1.Verify(payload, sig)

	case KeySpecRSA4096:
		if opts == nil || opts.Algorithm == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; no algorithm provided", len(payload), k.ID)
		}
		rsa4096 := crypto.RSAKeyPair{
			PublicKey: k.PublicKey,
		}
		return rsa4096.Verify(payload, sig, *opts.Algorithm)

	case KeySpecRSA3072:
		if opts == nil || opts.Algorithm == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; no algorithm provided", len(payload), k.ID)
		}
		rsa3072 := crypto.RSAKeyPair{
			PublicKey: k.PublicKey,
		}
		return rsa3072.Verify(payload, sig, *opts.Algorithm)

	case KeySpecRSA2048:
		if opts == nil || opts.Algorithm == nil {
			return fmt.Errorf("failed to verify signature of %d-byte payload using key: %s; no algorithm provided", len(payload), k.ID)
		}
		rsa2048 := crypto.RSAKeyPair{
			PublicKey: k.PublicKey,
		}
		return rsa2048.Verify(payload, sig, *opts.Algorithm)
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
			Message: common.StringOrNil(fmt.Sprintf("key type must be (%s or %s)", KeyTypeAsymmetric, KeyTypeSymmetric)),
		})
	}

	return len(k.Errors) == 0
}

func (o *SigningOptions) validateHDWalletOpts() (*accounts.DerivationPath, error) {
	if o.HDWallet == nil {
		// short-circuit to return default hd wallet options
		return crypto.DefaultHDDerivationPath(), nil
	}

	var path *accounts.DerivationPath

	if o.HDWallet.Path != nil {
		// validate other options were not provided
		if o.HDWallet.Purpose != nil || o.HDWallet.Coin != nil || o.HDWallet.CoinAbbr != nil || o.HDWallet.Account != nil || o.HDWallet.Change != nil || o.HDWallet.Index != nil {
			return nil, fmt.Errorf("derivation path was provided with other explicit hd wallet options")
		}

		// resolve the hd derivation path
		derivationPath, err := o.HDWallet.ResolvePath()
		if err != nil {
			common.Log.Warningf("failed to resolve hd derivation path; %s", err.Error())
			return nil, err
		}

		path = derivationPath
	} else {
		var err error

		purpose := o.HDWallet.Purpose
		if purpose == nil {
			_purpose := uint32(crypto.DefaultHDWalletPurpose)
			purpose = &_purpose
		}

		// resolve the coin from the hd derivation path
		coin, err := o.HDWallet.ResolveCoin()
		if err != nil {
			_coin := uint32(crypto.DefaultHDWalletCoin)
			coin = &_coin
		}

		account := o.HDWallet.Account
		if account == nil {
			_account := uint32(0)
			account = &_account
		}

		change := o.HDWallet.Change
		if change == nil {
			_change := uint32(0)
			change = &_change
		}

		index := o.HDWallet.Index
		if index == nil {
			_index := uint32(0)
			index = &_index
		}

		var pathstr string
		if change != nil {
			pathstr = fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", *purpose, *coin, *account, *change, *index)
		} else if index != nil {
			pathstr = fmt.Sprintf("m/%d'/%d'/%d'/%d", *purpose, *coin, *account, *index)
		} else {
			pathstr = fmt.Sprintf("m/%d'/%d'/%d'", *purpose, *coin, *account)
		}

		derivationPath, err := hdwallet.ParseDerivationPath(pathstr)
		if err != nil {
			common.Log.Warningf("failed to parse hd derivation path; %s", err.Error())
			return nil, err
		}

		path = &derivationPath
	}

	return path, nil
}

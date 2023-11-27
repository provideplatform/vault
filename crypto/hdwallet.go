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

package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/provideplatform/vault/common"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// DefaultHDWalletPurpose is the default purpose of the HD wallet
const DefaultHDWalletPurpose = uint32(44)

// DefaultHDWalletCoin is the default coin for HD wallets
const DefaultHDWalletCoin = HDWalletCoinCodeEthereum

// DefaultHDWalletSeedEntropy is default entropy for seed phrases (24 words)
const DefaultHDWalletSeedEntropy = 256

// DefaultHDWalletMnemonicValidationRetries is the default number of retries vault performs when validating HD wallet mnemonics
const DefaultHDWalletMnemonicValidationRetries = 10

// HDWalletCoinAbbrBTC is the standard abbreviation for native coin of the Bitcoin chain
const HDWalletCoinAbbrBTC = "BTC"

// HDWalletCoinAbbrETH is the standard abbreviation for native coin of the Ethereum chain
const HDWalletCoinAbbrETH = "ETH"

// HDWalletCoinCodeBitcoin from the BIP39 spec
const HDWalletCoinCodeBitcoin = uint32(0)

// HDWalletCoinCodeEthereum from the BIP39 spec
const HDWalletCoinCodeEthereum = uint32(60)

// DefaultRootDerivationPath is the root path to which custom derivation endpoints
// are appended. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc.
var DefaultRootDerivationPath = accounts.DefaultRootDerivationPath

// DefaultBaseDerivationPath is the base path from which custom derivation endpoints
// are incremented. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc
var DefaultBaseDerivationPath = accounts.DefaultBaseDerivationPath

// HDWallet is the internal struct for the top-level node within an HD wallet
type HDWallet struct {
	Path     *string `json:"hd_derivation_path,omitempty"` // placeholder for adding more advanced support for hd_derivation_path; not used... yet
	Purpose  *uint32 `json:"purpose,omitempty"`
	Coin     *uint32 `json:"coin,omitempty"`
	CoinAbbr *string `json:"coin_abbr,omitempty"`
	Account  *uint32 `json:"account,omitepty"`
	Change   *uint32 `json:"change,omitempty"`
	Index    *uint32 `json:"index,omitempty"`

	Seed       []byte `json:"-"` // contains the mnemonic seed phrase in bytes
	PublicKey  []byte `json:"-"` // contains the extended public key; in general it is safest NOT to share this
	PrivateKey []byte `json:"-"` // contains the extended private key; NEVER share this! it exists here to support ephemeral wallet creation...

	// extra fields needed for internal methods

	fixIssue172 bool
	mnemonic    string
	masterKey   *hdkeychain.ExtendedKey
	url         accounts.URL
	paths       map[ethcommon.Address]accounts.DerivationPath
	accounts    []accounts.Account
	stateLock   sync.RWMutex
}

// DefaultHDDerivationPath returns the default hd derivation path
func DefaultHDDerivationPath() *accounts.DerivationPath {
	purpose := DefaultHDWalletPurpose
	coin := DefaultHDWalletCoin
	account := uint32(0)
	change := uint32(0)
	index := uint32(0)

	pathstr := fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", purpose, coin, account, change, index)
	path, err := accounts.ParseDerivationPath(pathstr)
	if err != nil {
		common.Log.Debugf("failed to parse derivation path 1; %s", err.Error())
	}
	return &path
}

// ResolveCoin returns the coin as it should appear in the HD derivation path;
// order of precedence favors the `Coin` field; if unset, the `CoinAbbr` field is
// used next; with the presence of HD derivation path, it is prefered.
// Returns the coin specification (int) as it appears in the derivation path.
func (o *HDWallet) ResolveCoin() (*uint32, error) {
	var coin *uint32

	if o.Coin != nil {
		switch *o.Coin {
		case HDWalletCoinCodeBitcoin:
			_coin := uint32(HDWalletCoinCodeBitcoin)
			coin = &_coin
		case HDWalletCoinCodeEthereum:
			_coin := uint32(HDWalletCoinCodeEthereum)
			coin = &_coin
		default:
			return nil, fmt.Errorf("unsupported hd coin type: %d", *o.Coin)
		}
	} else if o.CoinAbbr != nil {
		switch *o.CoinAbbr {
		case HDWalletCoinAbbrBTC:
			_coin := uint32(HDWalletCoinCodeBitcoin)
			coin = &_coin
		case HDWalletCoinAbbrETH:
			_coin := uint32(HDWalletCoinCodeEthereum)
			coin = &_coin
		default:
			return nil, fmt.Errorf("unsupported hd coin abbreviation: %s", *o.CoinAbbr)
		}
	}

	if coin == nil {
		return nil, fmt.Errorf("failed to resolve coin")
	}

	return coin, nil
}

// ResolvePath parses and validates the HD derivation path set on options
func (o *HDWallet) ResolvePath() (*accounts.DerivationPath, error) {
	if o.Path == nil {
		return nil, errors.New("nil hd derivation path")
	}

	path, err := accounts.ParseDerivationPath(*o.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hd derivation path; %s", err.Error())
	}

	return &path, nil
}

// DeriveKey deterministically derives and returns a secp256k1 key
// from the given HD derivation path components
func (o *HDWallet) DeriveKey(path accounts.DerivationPath) (*Secp256k1, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered from panic during hd walley key derivation; %s", r)
		}
	}()

	// first recreate the hd wallet from the mnemonic
	wallet, err := newFromMnemonic(string(o.Seed))
	if err != nil {
		return nil, fmt.Errorf("error generating wallet from mnemonic %s", err.Error())
	}

	pathstr := path.String()

	acct, err := wallet.Derive(path, false)
	if err != nil {
		return nil, fmt.Errorf("error creating account with path %s; %s", pathstr, err.Error())
	}

	privatekey, err := wallet.privateKeyBytes(acct)
	if err != nil {
		return nil, fmt.Errorf("error generating private key for path %s; %s", pathstr, err.Error())
	}

	publickey, err := wallet.publicKeyBytes(acct)
	if err != nil {
		return nil, fmt.Errorf("error generating public key for path %s; %s", pathstr, err.Error())
	}

	address, err := wallet.addressHex(acct)
	if err != nil {
		return nil, fmt.Errorf("error generating address for path %s; %s", pathstr, err.Error())
	}

	secp256k1 := Secp256k1{
		Address:        &address,
		PrivateKey:     privatekey,
		PublicKey:      publickey,
		DerivationPath: &pathstr,
	}

	common.Log.Debugf("derived hd wallet key with derivation path %s; public key %s", pathstr, hex.EncodeToString(publickey))
	return &secp256k1, nil
}

// CreateHDWalletWithEntropy creates a mnemonic phrase in accordance with the BIP39 specification;
// the bitsize parameter sets the amount of entropy to use for the generated seed (i.e., 256 bit
// entropy will generate for a 24-word mnemonic)
// TODO split this up so we're just generating the seed phrase here, and then creating the wallet from it
// TODO and sort out the FIXME
func CreateHDWalletWithEntropy(bitsize int) (*HDWallet, error) {
	// first we generate a random mnemonic using `bitsize` bits of entropy
	entropy, err := bip39.NewEntropy(bitsize)
	if err != nil {
		common.Log.Warningf("failed to create entropy for HD wallet mnemonic; %s", err.Error())
		return nil, err
	}

	// this entropy is used to generate a seed phrase
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		common.Log.Warningf("failed to generate HD wallet mnemonic from %d-bit entropy; %s", len(entropy)*8, err.Error())
		return nil, err
	}

	// make sure we can use the mnemonic to generate a HD wallet
	// validate the mnemonic, retrying if it fails
	err = common.Retry(DefaultHDWalletMnemonicValidationRetries, 0*time.Second, func() (err error) {
		err = validateHDWalletMnemonic(mnemonic)
		return
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate provided BIP39 mnemonic. Error: %s", err.Error())
	}

	mnemonicBytes := []byte(mnemonic)
	masterKey, err := bip32.NewMasterKey(mnemonicBytes)
	if err != nil {
		return nil, fmt.Errorf("error resolving master extended key for HD wallet; %s", err.Error())
	}

	xpub := masterKey.PublicKey().String()
	xpubBytes := []byte(xpub)

	// return a new HDWallet and store the generated mnemonic as the `Seed`
	return &HDWallet{
		Seed:      mnemonicBytes, // FIXME -- see https://github.com/provideplatform/vault/issues/3
		PublicKey: xpubBytes,
	}, nil
}

// CreateHDWalletFromSeedPhrase creates a HD wallet using the generated seed phrase
func CreateHDWalletFromSeedPhrase(mnemonic string) (*HDWallet, error) {

	// validate the mnemonic, retrying if it fails
	err := common.Retry(DefaultHDWalletMnemonicValidationRetries, 0*time.Second, func() (err error) {
		err = validateHDWalletMnemonic(mnemonic)
		return
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate provided BIP39 mnemonic. Error: %s", err.Error())
	}

	mnemonicBytes := []byte(mnemonic)
	masterKey, err := bip32.NewMasterKey(mnemonicBytes)
	if err != nil {
		return nil, fmt.Errorf("error resolving master extended key for HD wallet; %s", err.Error())
	}

	xpub := masterKey.PublicKey().String()
	xpubBytes := []byte(xpub)

	// return a new HDWallet and store the provided mnemonic as the `Seed`
	return &HDWallet{
		Seed:      mnemonicBytes, // FIXME -- see https://github.com/provideplatform/vault/issues/3
		PublicKey: xpubBytes,
	}, nil
}

func validateHDWalletMnemonic(mnemonic string) error {

	// make sure we can use the mnemonic to generate a HD wallet
	_, err := newFromMnemonic(mnemonic)
	if err != nil {
		return fmt.Errorf("error generating HD wallet from mnemonic %s", err.Error())
	}
	return nil
}

// GetEntropyFromMnemonic is used by the mnemonic-based unsealer key
func GetEntropyFromMnemonic(mnemonic string) ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	return entropy, nil
}

// newSeedFromMnemonic returns a BIP-39 seed based on a BIP-39 mnemonic.
func newSeedFromMnemonic(mnemonic string) ([]byte, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	return bip39.NewSeedWithErrorChecking(mnemonic, "")
}

// newFromMnemonic returns a new HD wallet from a BIP-39 mnemonic.
func newFromMnemonic(mnemonic string) (*HDWallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	seed, err := newSeedFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	wallet, err := newHDWallet(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic

	return wallet, nil
}

func newHDWallet(seed []byte) (*HDWallet, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return &HDWallet{
		masterKey: masterKey,
		Seed:      seed,
		accounts:  []accounts.Account{},
		paths:     map[ethcommon.Address]accounts.DerivationPath{},
	}, nil
}

// Derive implements accounts.Wallet, deriving a new account at the specific
// derivation path. If pin is set to true, the account will be added to the list
// of tracked accounts.
func (w *HDWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	// Try to derive the actual account and update its URL if successful
	w.stateLock.RLock() // Avoid device disappearing during derivation

	address, err := w.deriveAddress(path)

	w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	if err != nil {
		return accounts.Account{}, err
	}

	account := accounts.Account{
		Address: address,
		URL: accounts.URL{
			Scheme: "",
			Path:   path.String(),
		},
	}

	if !pin {
		return account, nil
	}

	// Pinning needs to modify the state
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = path
	}

	return account, nil
}

// deriveAddress derives the account address of the derivation path.
func (w *HDWallet) deriveAddress(path accounts.DerivationPath) (ethcommon.Address, error) {
	publicKeyECDSA, err := w.derivePublicKey(path)
	if err != nil {
		return ethcommon.Address{}, err
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address, nil
}

// derivePrivateKey derives the private key of the derivation path.
func (w *HDWallet) derivePrivateKey(path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		if w.fixIssue172 && key.IsAffectedByIssue172() {
			key, err = key.Derive(n)
		} else {
			key, err = key.DeriveNonStandard(n)
		}
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

// derivePublicKey derives the public key of the derivation path.
func (w *HDWallet) derivePublicKey(path accounts.DerivationPath) (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}

	return publicKeyECDSA, nil
}

// address returns the address of the account.
func (w *HDWallet) address(account accounts.Account) (ethcommon.Address, error) {
	publicKey, err := w.publicKey(account)
	if err != nil {
		return ethcommon.Address{}, err
	}

	return crypto.PubkeyToAddress(*publicKey), nil
}

// AddressBytes returns the address in bytes format of the account.
func (w *HDWallet) addressBytes(account accounts.Account) ([]byte, error) {
	address, err := w.address(account)
	if err != nil {
		return nil, err
	}
	return address.Bytes(), nil
}

// addressHex returns the address in hex string format of the account.
func (w *HDWallet) addressHex(account accounts.Account) (string, error) {
	address, err := w.address(account)
	if err != nil {
		return "", err
	}
	return address.Hex(), nil
}

// privateKeyBytes returns the ECDSA private key in bytes format of the account.
func (w *HDWallet) privateKeyBytes(account accounts.Account) ([]byte, error) {
	privateKey, err := w.privateKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSA(privateKey), nil
}

// PrivateKeyHex return the ECDSA private key in hex string format of the account.
func (w *HDWallet) privateKeyHex(account accounts.Account) (string, error) {
	privateKeyBytes, err := w.privateKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(privateKeyBytes)[2:], nil
}

// privateKey returns the ECDSA private key of the account.
func (w *HDWallet) privateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	path, err := accounts.ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePrivateKey(path)
}

// publicKey returns the ECDSA public key of the account.
func (w *HDWallet) publicKey(account accounts.Account) (*ecdsa.PublicKey, error) {
	path, err := accounts.ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePublicKey(path)
}

// publicKeyBytes returns the ECDSA public key in bytes format of the account.
func (w *HDWallet) publicKeyBytes(account accounts.Account) ([]byte, error) {
	publicKey, err := w.publicKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSAPub(publicKey), nil
}

// publicKeyHex return the ECDSA public key in hex string format of the account.
func (w *HDWallet) publicKeyHex(account accounts.Account) (string, error) {
	publicKeyBytes, err := w.publicKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(publicKeyBytes)[4:], nil
}

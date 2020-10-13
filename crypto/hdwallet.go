package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/provideapp/vault/common"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// DefaultHDWalletPurpose is the default purpose of the HD wallet
const DefaultHDWalletPurpose = uint32(44)

// DefaultHDWalletCoin is the default coin for HD wallets
const DefaultHDWalletCoin = HDWalletCoinCodeEthereum

// DefaultHDWalletSeedEntropy is default entropy for seed phrases (24 words)
const DefaultHDWalletSeedEntropy = 256

// HDWalletCoinAbbrBTC is the standard abbreviation for native coin of the Bitcoin chain
const HDWalletCoinAbbrBTC = "BTC"

// HDWalletCoinAbbrETH is the standard abbreviation for native coin of the Ethereum chain
const HDWalletCoinAbbrETH = "ETH"

// HDWalletCoinCodeBitcoin from the BIP39 spec
const HDWalletCoinCodeBitcoin = uint32(0)

// HDWalletCoinCodeEthereum from the BIP39 spec
const HDWalletCoinCodeEthereum = uint32(60)

// HDWallet is the internal struct for the top-level node within an HD wallet
type HDWallet struct {
	Path     *string `json:"hd_derivation_path,omitempty"` // placeholder for adding more advanced support for hd_derivation_path; not used... yet
	Purpose  *uint32 `json:"purpose,omitempty"`
	Coin     *uint32 `json:"coin,omitempty"`
	CoinAbbr *string `json:"coin_abbr,omitempty"`
	Account  *uint32 `json:"account,omitepty"`
	Change   *uint32 `json:"change,omitempty"`
	Index    *uint32 `json:"index,omitempty"`

	Seed       *[]byte `json:"-"` // contains the mnemonic seed phrase in bytes
	PublicKey  *[]byte `json:"-"` // contains the extended public key; in general it is safest NOT to share this
	PrivateKey *[]byte `json:"-"` // contains the extended private key; NEVER share this! it exists here to support ephemeral wallet creation...
}

// DefaultHDWalletWithIndex returns hd wallet options, initialized with the given index
func DefaultHDWalletWithIndex(index *uint32) *HDWallet {
	purpose := DefaultHDWalletPurpose
	coin := DefaultHDWalletCoin
	change := uint32(0)

	idx := uint32(0)
	if index != nil {
		idx = *index
	}

	return &HDWallet{
		Purpose: &purpose,
		Coin:    &coin,
		Change:  &change,
		Index:   &idx,
	}
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

	path, err := hdwallet.ParseDerivationPath(*o.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hd derivation path; %s", err.Error())
	}

	return &path, nil
}

// CreateKeyFromWallet deterministically creates a secp256k1 key
// include private and public key and ETH address
// which can be used to sign Ethereum transactions
func (o *HDWallet) CreateKeyFromWallet(purpose, coin, index uint32) (*Secp256k1, error) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered from panic during CreateKeyFromWallet(); %s", r)
		}
	}()

	// first recreate the hd wallet from the mnemonic
	wallet, err := hdwallet.NewFromMnemonic(string(*o.Seed))
	if err != nil {
		return nil, fmt.Errorf("error generating wallet from mnemonic %s", err.Error())
	}

	pathstr := fmt.Sprintf("m/%d'/%d'/0'/0/%d", purpose, coin, index)
	path := hdwallet.MustParseDerivationPath(pathstr)

	account, err := wallet.Derive(path, true)
	if err != nil {
		return nil, fmt.Errorf("error creating account with path %s. Error %s", pathstr, err.Error())
	}

	privatekey, err := wallet.PrivateKeyBytes(account)
	if err != nil {
		return nil, fmt.Errorf("error generating private key for path %s. Error: %s", pathstr, err.Error())
	}

	publickey, err := wallet.PublicKeyBytes(account)
	if err != nil {
		return nil, fmt.Errorf("error generating public key for path %s. Error: %s", pathstr, err.Error())
	}

	address, err := wallet.AddressHex(account)
	if err != nil {
		return nil, fmt.Errorf("error generating address for path %s. Error: %s", pathstr, err.Error())
	}

	secp256k1 := Secp256k1{
		Address:        &address,
		PrivateKey:     &privatekey,
		PublicKey:      &publickey,
		DerivationPath: &pathstr,
	}

	common.Log.Debugf("generated hd wallet %d key with public key 0x%s", coin, hex.EncodeToString(publickey))
	return &secp256k1, nil
}

// CreateHDWalletSeedPhrase creates a mnemonic phrase in accordance with the BIP39 specification;
// the bitsize parameter sets the amount of entropy to use for the generated seed (i.e., 256 bit
// entropy will generate for a 24-word mnemonic)
func CreateHDWalletSeedPhrase(bitsize int) (*HDWallet, error) {
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
	_, err = hdwallet.NewFromMnemonic(mnemonic) // FIXME? make sure this cannot fail on occasion; if it can, retry until it works...
	if err != nil {
		return nil, fmt.Errorf("error generating HD wallet from mnemonic %s", err.Error())
	}

	mnemonicBytes := []byte(mnemonic)
	masterKey, err := bip32.NewMasterKey(mnemonicBytes)
	if err != nil {
		return nil, fmt.Errorf("error resolving extended public key for HD wallet; %s", err.Error())
	}

	xpub := masterKey.PublicKey().String()
	xpubBytes := []byte(xpub)

	// return a new HDWallet and store the generated mnemonic as the `Seed`
	return &HDWallet{
		Seed:      &mnemonicBytes, // FIXME -- see https://github.com/provideapp/vault/issues/3
		PublicKey: &xpubBytes,
	}, nil
}

// GetEntropyFromMnemonic is used by the mnemonic-based unsealer key
func GetEntropyFromMnemonic(mnemonic string) ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	return entropy, nil
}

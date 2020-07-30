package crypto

import (
	"encoding/hex"
	"fmt"
	"strconv"

	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/provideapp/vault/common"
	"github.com/tyler-smith/go-bip39"
)

// HDWallet is the internal struct for an asymmetric keypair
type HDWallet struct {
	Seed *[]byte // contains the mnemonic seed phrase
}

// EthereumCoin is the coin index of Ethereum in the BIP39 spec
const EthereumCoin = uint32(60)

// BitcoinCoin is the coin index of Bitcoin in the BIP39 spec
const BitcoinCoin = uint32(0)

// CreateKeyFromWallet deterministically creates a secp256k1 key
// include private and public key and ETH address
// which can be used to sign Ethereum transactions
func (w *HDWallet) CreateKeyFromWallet(coin, index uint32) (*Secp256k1, error) {

	var coinPath string
	switch coin {
	case EthereumCoin:
		coinPath = "60"
	case BitcoinCoin:
		coinPath = "0"
	default:
		//not supported
		return nil, fmt.Errorf("unsupported coin type")
	}

	// first recreate the hd wallet from the mnemonic
	wallet, err := hdwallet.NewFromMnemonic(string(*w.Seed))
	if err != nil {
		return nil, fmt.Errorf("error generating wallet from mnemonic %s", err.Error())
	}

	pathstr := fmt.Sprintf("m/44'/%s'/0'/0/%s", coinPath, strconv.Itoa(int(index)))
	common.Log.Debugf("path string generated: %s", pathstr)

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

	secp256k1 := Secp256k1{}
	secp256k1.Address = &address
	secp256k1.PrivateKey = &privatekey
	secp256k1.PublicKey = &publickey
	common.Log.Debugf("generated key with public key %s", hex.EncodeToString(publickey))
	return &secp256k1, nil
}

// CreateHDWalletSeedPhrase creates a 24-word mnemonic phrase
// in accordance with the BIP39 specification
func CreateHDWalletSeedPhrase() (*HDWallet, error) {

	// first we generate a random mnemonic (256 bits of entropy)
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		common.Log.Warningf("failed to create entropy for HD wallet mnemonic; %s", err.Error())
		return nil, err
	}

	// this entropy is used to generate a 24-word seed phrase
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		common.Log.Warningf("failed to generate HD wallet mnemonic from %d-bit entropy; %s", len(entropy)*8, err.Error())
		return nil, err
	}

	mnemonicAsBytes := []byte(mnemonic)
	// make sure we can use the mnemonic to generate a HD wallet
	_, err = hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("error generating HD wallet from mnemonic %s", err.Error())
	}

	// create a new EthHDWalletinstance
	// and store the generated mnemonic in the Seed field
	// this will be then stored in the Seed column in the db
	hdWallet := HDWallet{}
	hdWallet.Seed = &mnemonicAsBytes

	return &hdWallet, nil
}

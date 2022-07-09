package cryptoutils

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

func GenTrustKeysMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return string(mnemonic), nil
}

func GetTrustKeysPrivateKeyFromMnemonic(mnemonic string) (*ecdsa.PrivateKey, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	wallet, err := hdwallet.NewFromSeed(entropy)
	if err != nil {
		return nil, err
	}
	path := hdwallet.MustParseDerivationPath("m/69'/88'/0/0")
	account, err := wallet.Derive(path, true)
	if err != nil {
		return nil, err

	}
	return wallet.PrivateKey(account)
}

func GenMetamaskMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return string(mnemonic), nil
}

func GetMetamaskPrivateKeyFromMnemonic(mnemonic string) (*ecdsa.PrivateKey, error) {
	seed := bip39.NewSeed(mnemonic, "")
	wallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		return nil, err
	}
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, true)
	if err != nil {
		return nil, err
	}
	return wallet.PrivateKey(account)
}

func GetEthereumAddressHex(publickey ecdsa.PublicKey) string {
	return crypto.PubkeyToAddress(publickey).Hex()
}

package cryptoutils

import (
	"github.com/ethereum/go-ethereum/crypto"

	"testing"
)

func TestImportMetamaskMnemonic(t *testing.T) {
	address := "0x430F650693F017Fc90c61749DA3601519CAEAE45"
	mnemonic := "cotton dose elegant enough gas amazing twist mirror put response food outdoor suffer minimum remember elegant around dance trick bunker expand grace siren supreme"

	privateKey, err := GetMetamaskPrivateKeyFromMnemonic(mnemonic)
	if err != nil {
		t.Error("get private key failed", err)
	}

	publickey := privateKey.PublicKey
	resultAdress := crypto.PubkeyToAddress(publickey).Hex()

	if address != resultAdress {
		t.Error("resutl pubkey from mnemonic is", resultAdress, "not equal", address)
	}
}

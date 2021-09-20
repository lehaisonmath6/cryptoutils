package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func CheckSignature(publickeyHex, signature, message string) bool {

	aHash := Hash256(message)
	sigBin, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	aRecoveredPub, errSig := crypto.SigToPub(aHash, sigBin)
	if errSig != nil {
		return false
	}

	compressedPub := crypto.CompressPubkey(aRecoveredPub)
	return publickeyHex == hex.EncodeToString(compressedPub)
}

func GetPublicKeyHex(privateKey *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.CompressPubkey(&privateKey.PublicKey))
}

func GetPrivateKeyFromHex(privatekeyHex string) (*ecdsa.PrivateKey, error) {
	privatekeyBytes, err := hex.DecodeString(privatekeyHex)
	if err != nil {
		return nil, err
	}
	return crypto.ToECDSA(privatekeyBytes)
}

func GenKey(seed string) *ecdsa.PrivateKey {
	aHash := Hash256(seed)
	aKey, _ := crypto.ToECDSA(aHash)
	return aKey
}

func SignMessage(privatekey *ecdsa.PrivateKey, message string) (string, error) {
	signBytes, err := crypto.Sign(Hash256(message), privatekey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signBytes), nil
}

func EncryptMessage(publickeyHex string, message string) (string, error) {
	publickeyBytes, err := hex.DecodeString(publickeyHex)
	if err != nil {
		return "", err
	}
	publickey, err := crypto.DecompressPubkey(publickeyBytes)
	if err != nil {
		return "", err
	}
	keyEncrypt := ecies.ImportECDSAPublic(publickey)
	cipherBytes, err := ecies.Encrypt(rand.Reader, keyEncrypt, []byte(message), nil, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), err
}

func EncryptHexMessage(publickeyHex string, message string) (string, error) {
	publickeyBytes, err := hex.DecodeString(publickeyHex)
	if err != nil {
		return "", err
	}
	publickey, err := crypto.DecompressPubkey(publickeyBytes)
	if err != nil {
		return "", err
	}
	keyEncrypt := ecies.ImportECDSAPublic(publickey)
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		return "", err
	}
	cipherBytes, err := ecies.Encrypt(rand.Reader, keyEncrypt, messageBytes, nil, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), err
}

func DecryptMessage(privatekey *ecdsa.PrivateKey, cipherMessage string) (string, error) {
	cipherMessageBytes, err := hex.DecodeString(cipherMessage)
	if err != nil {
		return "", err
	}
	decryptBytes, err := ecies.ImportECDSA(privatekey).Decrypt(cipherMessageBytes, nil, nil)
	if err != nil {
		return "", err
	}
	return string(decryptBytes), nil
}

func DecryptHexMessage(privatekey *ecdsa.PrivateKey, cipherMessage string) (string, error) {
	cipherMessageBytes, err := hex.DecodeString(cipherMessage)
	if err != nil {
		return "", err
	}
	decryptBytes, err := ecies.ImportECDSA(privatekey).Decrypt(cipherMessageBytes, nil, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decryptBytes), nil
}

func ChecSignatureHex(publickeyHex, signature, message string) bool {
	messBytes, err := hex.DecodeString(message)
	if err != nil {
		return false
	}
	aHash := HashBytes(messBytes)
	sigBin, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	aRecoveredPub, errSig := crypto.SigToPub(aHash, sigBin)
	if errSig != nil {
		return false
	}

	compressedPub := crypto.CompressPubkey(aRecoveredPub)
	return publickeyHex == hex.EncodeToString(compressedPub)
}

func SignHexMessage(privatekey *ecdsa.PrivateKey, hexmessage string) (string, error) {
	messageBytes, err := hex.DecodeString(hexmessage)
	if err != nil {
		return "", err
	}
	signBytes, err := crypto.Sign(HashBytes(messageBytes), privatekey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signBytes), nil
}

package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {

	secretText := "Hal Finney was Satoshi Nakamoto."
	pubKeyIKnowInHex := "0433e59593e3ac1dbf8e7167250c49f5a75f38d37afacc71df97755f3d56cd436c68ee7190f03a9eacddf88911226f1464694e2b9397e1c023aea09efc18591e00"

	encryptedText, err := EncryptECWithPublicKey(pubKeyIKnowInHex, secretText)
	if err != nil {
		log.Fatal("Error encrypting text: ", err)
	}

	log.Printf("Encrypted text in hexa: %x\n", encryptedText)

	log.Println("===========================================")

	myPrivateKey := "NoisTenho32BitsVocePodeAcreditar"

	decryptedText, err := DecryptWithECPrivateKey(myPrivateKey, encryptedText)
	if err != nil {
		log.Fatal("Error decrypting text: ", err)
	}

	if !bytes.Equal([]byte(secretText), []byte(decryptedText)) {
		log.Fatal("Ops... decrypted data doesn't match original ", encryptedText, "  ", decryptedText)
	}

	log.Println("Perfect!")
	log.Println("In ", secretText, " - Out ", decryptedText)

}

//EncryptECWithPublicKey using EC (with secp256k1 parameters) public key in hexadecimal string format encrypt a string
func EncryptECWithPublicKey(pubKeyInHexaString, textToEncrypt string) (encryptedText string, err error) {
	err = nil
	pubKeyInHexaString = strings.TrimPrefix(pubKeyInHexaString, "0x")
	dst := make([]byte, hex.DecodedLen(len(pubKeyInHexaString)))
	chavePublicaEmInt, err := hex.Decode(dst, []byte(pubKeyInHexaString))
	if err != nil {
		log.Fatal("[EncryptECDSAWithPublicKey] Error decoding pubKey to Int: ", err.Error())
		return
	}
	dst = dst[:chavePublicaEmInt]

	//log.Printf("[EncryptECDSAWithPublicKey]  PubKey: %s\n", dst)
	chavePublicaECDSA, err := secp256k1.ParsePubKey(dst)
	if err != nil {
		log.Fatal("Error parsing PubKey:", err)
		return
	}

	out, err := secp256k1.Encrypt(chavePublicaECDSA, []byte(textToEncrypt))
	if err != nil {
		log.Fatal("[EncryptECDSAWithPublicKey] failed to encrypt: ", err)
		return
	}
	encryptedText = string(out)
	return
}

//DecryptWithECPrivateKey decrypt a text using EC (with secp256k1 parameters) private key
func DecryptWithECPrivateKey(privateKey, encryptedText string) (decryptedText string, err error) {
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(privateKey))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	chavePrivadaDecred := secp256k1.NewPrivateKey(chavePrivadaEmECDSA.D)
	if err != nil {
		log.Fatal("[DecryptWithECPrivateKey] Error generating private key from text: ", err)
		return
	}

	dec, err := secp256k1.Decrypt(chavePrivadaDecred, []byte(encryptedText))
	if err != nil {
		log.Fatal("[DecryptWithECPrivateKey] failed to decrypt:", err)
	}
	decryptedText = string(dec)
	return
}

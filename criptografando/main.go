package main

import (
	"bytes"
	"encoding/hex"
	"log"

	"github.com/decred/dcrd/dcrec/secp256k1"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {

	in := []byte("Hey there dude. How are you doing? This is a test.")

	//chavePublica := secp256k1.NewPublicKey(chavePrivadaEmECDSA.X, chavePrivadaEmECDSA.Y)
	chavePublica, err := secp256k1.ParsePubKey([]byte("0x04f7270a93ba0c2ec6686797da050bd602293a3d6cc53d6b86758d44cae22813e9e864682e9e9d351bbfb65cadedf62d2687c78bf2fd9146be23172026f001ecdd"))
	if err != nil {
		log.Fatal("Erro ao fazer o parse da chave publica ", err)
	}

	out, err := secp256k1.Encrypt(chavePublica, in)
	if err != nil {
		log.Fatal("failed to encrypt:", err)
	}

	chavePrivada := "EuTenho32BitsVocePodeAcreditar!!"
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(chavePrivada))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	chavePrivadaDecred := secp256k1.NewPrivateKey(chavePrivadaEmECDSA.D)
	if err != nil {
		log.Fatal("Erro ao gerar a chave privada em ECDSA ", err)
	}

	dec, err := secp256k1.Decrypt(chavePrivadaDecred, out)
	if err != nil {
		log.Fatal("failed to decrypt:", err)
	}

	if !bytes.Equal(in, dec) {
		log.Fatal("decrypted data doesn't match original")
	}

	log.Println("Sucesso !")
	log.Println("Entrada ", string(in), " - Saida ", string(dec))

}

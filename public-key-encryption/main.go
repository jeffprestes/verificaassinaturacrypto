package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"

	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	chavePrivada := "PalmeirasNaoTemMundial51NaoConta"
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(chavePrivada))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	if err != nil {
		log.Fatal("Erro ao gerar a chave privada em ECDSA ", err)
	}
	chavePrivadaEmECIES, err := ecies.NewPrivateKeyFromHex(chavePrivadaEmHexadecimal)
	if err != nil {
		log.Fatal("Erro ao gerar a chave privada em ECIES ", err)
	}

	chavePublica := chavePrivadaEmECDSA.Public()
	chavePublicaEmECDSA, ok := chavePublica.(*ecdsa.PublicKey)
	chavePublicaECIES := new(ecies.PublicKey)
	chavePublicaECIES.X = chavePublicaEmECDSA.X
	chavePublicaECIES.Y = chavePublicaEmECDSA.Y
	chavePublicaECIES.Curve = chavePublicaEmECDSA.Curve
	if !ok {
		log.Fatal("Nao foi possivel fazer o casting da chave publica para ECDSA")
	}
	if err != nil {
		panic(err)
	}
	log.Println("key pair has been generated")

	contaEthereum := crypto.PubkeyToAddress(*chavePublicaEmECDSA)

	ciphertext, err := ecies.Encrypt(chavePublicaECIES, []byte("THIS IS THE TEST"))
	if err != nil {
		panic(err)
	}
	log.Printf("plaintext encrypted: %v\n", ciphertext)

	plaintext, err := ecies.Decrypt(chavePrivadaEmECIES, ciphertext)
	if err != nil {
		panic(err)
	}
	log.Printf("ciphertext decrypted: %s\n", string(plaintext))
	log.Println("Ethereum account: ", contaEthereum.Hex())
}

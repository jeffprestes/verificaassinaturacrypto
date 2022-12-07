package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	chavePrivada := "EuTenho32BitsVocePodeAcreditar!!"
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(chavePrivada))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	if err != nil {
		log.Fatal("Erro ao gerar a chave privada em ECDSA ", err)
	}

	chavePublica := chavePrivadaEmECDSA.Public()
	chavePublicaEmECDSA, ok := chavePublica.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Nao foi possivel fazer o casting da chave publica para ECDSA")
	}

	contaEthereum := crypto.PubkeyToAddress(*chavePublicaEmECDSA)

	log.Println("Temos as chaves...")
	log.Println("")
	log.Println("Chave privada ", chavePrivada)
	log.Println("")
	log.Println("Chave privada em Hexadecimal ", chavePrivadaEmHexadecimal)
	log.Println("")
	log.Printf("Chave privada em ECDSA %+v\n\n", chavePrivadaEmECDSA)
	log.Printf("Objeto Chave publica %+v\n\n", chavePublica)
	log.Printf("Objeto Chave publica em ECDSA %+v\n\n", chavePublicaEmECDSA)
	log.Printf("Conta Ethereum %s\n\n\n", contaEthereum.String())

	chavePublicaEmBytes := crypto.FromECDSAPub(chavePublicaEmECDSA)
	chavePublicaEmHexaString := hexutil.Encode(chavePublicaEmBytes)
	log.Println("Chave publica em Hexadecimal ", chavePublicaEmHexaString)

	dado := "Eu vou assinar esse texto aqui"
	hash := crypto.Keccak256Hash([]byte(dado))
	log.Printf("Hash do dado a ser assinado %+v\n\n", hash.String())

	assinatura, err := crypto.Sign(hash.Bytes(), chavePrivadaEmECDSA)
	if err != nil {
		log.Fatal("Erro ao assinar o dado ", err)
	}

	log.Printf("\nO dado assinado em hexa: %s\nA chave publica em Hexa: %s\n",
		hexutil.Encode(assinatura),
		chavePublicaEmHexaString)
}

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

	log.Println("Temos as chaves...")
	log.Println("Chave privada ", chavePrivada)
	log.Println("Chave privada em Hexadecimal ", chavePrivadaEmHexadecimal)
	log.Printf("Chave privada em ECDSA %+v\n", chavePrivadaEmECDSA)
	log.Printf("Objeto Chave publica %+v\n", chavePublica)
	log.Printf("Objeto Chave publica em ECDSA %+v\n", chavePublicaEmECDSA)

	chavePublicaEmBytes := crypto.FromECDSAPub(chavePublicaEmECDSA)
	chavePublicaEmHexaString := hexutil.Encode(chavePublicaEmBytes)
	log.Println("Chave publica em Hexadecimal ", chavePublicaEmHexaString)

	dado := "Eu vou assinar esse texto aqui"
	hash := crypto.Keccak256Hash([]byte(dado))
	log.Printf("Hash do dado a ser assinado %+v\n", hash.String())

	assinatura, err := crypto.Sign(hash.Bytes(), chavePrivadaEmECDSA)
	if err != nil {
		log.Fatal("Erro ao assinar o dado ", err)
	}

	assinaturaChavePublica, err := crypto.Ecrecover(hash.Bytes(), assinatura)
	if err != nil {
		log.Fatalf("Erro ao gerar chave publica da assinatura %+v\n", err)
	}

	log.Printf("O dado assinado em hexa: %s\n", hexutil.Encode(assinaturaChavePublica))
}

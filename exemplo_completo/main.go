package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	chavePrivada := "NoisTenho32BitsVocePodeAcreditar"
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
	log.Printf("Chave publica %+v\n", chavePublica)
	log.Printf("Chave publica em ECDSA %+v\n", chavePublicaEmECDSA)

	chavePublicaEmBytes := crypto.FromECDSAPub(chavePublicaEmECDSA)
	chavePublicaEmHexaString := hexutil.Encode(chavePublicaEmBytes)
	log.Printf("Chave publica em Texto [%x] - Len: %d\n", string(chavePublicaEmBytes), len(string(chavePublicaEmBytes)))
	log.Println("Chave publica em Hexadecimal ", chavePublicaEmHexaString, " Len: ", len(chavePublicaEmHexaString), " O que e : ", chavePublicaEmBytes[0])

	dado := "Eu vou assinar esse texto aqui"
	hash := crypto.Keccak256Hash([]byte(dado))
	log.Printf("Hash do dado a ser assinado %+v\n", hash.String())

	assinatura, err := crypto.Sign(hash.Bytes(), chavePrivadaEmECDSA)
	if err != nil {
		log.Fatal("Erro ao assinar o dado ", err)
	}
	log.Printf("O dado assinado em hexa: %s\n", hexutil.Encode(assinatura))

	assinaturaChavePublica, err := crypto.Ecrecover(hash.Bytes(), assinatura)
	if err != nil {
		log.Fatalf("Erro ao gerar chave publica da assinatura %+v\n", err)
	}

	ehValido := bytes.Equal(assinaturaChavePublica, chavePublicaEmBytes)
	log.Println("A assinatura esta valida? ", ehValido)

	assinaturaChavePublicaECDSA, err := crypto.SigToPub(hash.Bytes(), assinatura)
	if err != nil {
		log.Fatalf("Erro ao gerar chave publica da assinatura em ECDSA %+v\n", err)
	}

	assinaturaChavePublicaECDSAEmBytes := crypto.FromECDSAPub(assinaturaChavePublicaECDSA)

	ehValido = bytes.Equal(assinaturaChavePublicaECDSAEmBytes, chavePublicaEmBytes)
	log.Println("A assinatura esta valida? ", ehValido)

	assinaturaSemRecoverID := assinatura[:len(assinatura)-1]
	verificado := crypto.VerifySignature(chavePublicaEmBytes, hash.Bytes(), assinaturaSemRecoverID)
	log.Println("A assinatura esta verificada? ", verificado)
}

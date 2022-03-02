package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	chavePrivada := "0004Tenho32BitsVocePodeAcreditar"
	chavePrivadaEmHexadecimal := hex.EncodeToString([]byte(chavePrivada))
	chavePrivadaEmECDSA, err := crypto.HexToECDSA(chavePrivadaEmHexadecimal)
	if err != nil {
		fmt.Print("Erro ao gerar a chave privada em ECDSA ", err)
		os.Exit(0)
	}

	chavePublica := chavePrivadaEmECDSA.Public()
	chavePublicaEmECDSA, ok := chavePublica.(*ecdsa.PublicKey)
	if !ok {
		fmt.Print("Nao foi possivel fazer o casting da chave publica para ECDSA")
		os.Exit(0)
	}

	fmt.Printf("\n")
	fmt.Printf("\n")
	fmt.Println("Temos a chave privada ", chavePrivada)
	fmt.Println("Chave privada em Hexadecimal ", chavePrivadaEmHexadecimal)
	fmt.Printf("\n")
	fmt.Printf("Chave privada em ECDSA %+v\n", chavePrivadaEmECDSA)
	fmt.Printf("\n")
	fmt.Printf("Chave publica %+v\n", chavePublica)
	fmt.Printf("\n")
	fmt.Printf("Chave publica em ECDSA %+v\n", chavePublicaEmECDSA)
	fmt.Printf("\n")

	chavePublicaEmBytes := crypto.FromECDSAPub(chavePublicaEmECDSA)
	chavePublicaEmHexaString := hexutil.Encode(chavePublicaEmBytes)
	fmt.Printf("Chave publica em Texto [%x] - Len: %d\n", string(chavePublicaEmBytes), len(string(chavePublicaEmBytes)))
	fmt.Printf("\n")
	fmt.Println("Chave publica em Hexadecimal ", chavePublicaEmHexaString, " Len: ", len(chavePublicaEmHexaString), " O que e : ", chavePublicaEmBytes[0])

	dado := "Eu vou assinar esse texto aqui"
	hash := crypto.Keccak256Hash([]byte(dado))
	fmt.Printf("\n")
	fmt.Println("Texto a ser assinado: ", dado)
	fmt.Printf("Hash do dado a ser assinado %+v\n", hash.String())

	assinatura, err := crypto.Sign(hash.Bytes(), chavePrivadaEmECDSA)
	if err != nil {
		fmt.Print("Erro ao assinar o dado ", err)
		os.Exit(0)
	}
	fmt.Printf("O dado assinado em hexa: %s\n", hexutil.Encode(assinatura))

	assinaturaChavePublica, err := crypto.Ecrecover(hash.Bytes(), assinatura)
	if err != nil {
		fmt.Printf("Erro ao gerar chave publica da assinatura %+v\n", err)
		os.Exit(0)
	}

	fmt.Printf("\n")
	ehValido := bytes.Equal(assinaturaChavePublica, chavePublicaEmBytes)
	fmt.Println("A assinatura esta valida? ", ehValido)

	// assinaturaChavePublicaECDSA, err := crypto.SigToPub(hash.Bytes(), assinatura)
	// if err != nil {
	// 	fmt.Printf("Erro ao gerar chave publica da assinatura em ECDSA %+v\n", err)
	// 	os.Exit(0)
	// }
	// assinaturaChavePublicaECDSAEmBytes := crypto.FromECDSAPub(assinaturaChavePublicaECDSA)
	// ehValido = bytes.Equal(assinaturaChavePublicaECDSAEmBytes, chavePublicaEmBytes)
	// fmt.Println("A assinatura esta valida? ", ehValido)

	assinaturaSemRecoverID := assinatura[:len(assinatura)-1]
	verificado := crypto.VerifySignature(chavePublicaEmBytes, hash.Bytes(), assinaturaSemRecoverID)
	fmt.Println("A assinatura esta verificada? ", verificado)
	fmt.Printf("\n")
	fmt.Printf("\n")
}

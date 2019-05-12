package main

import (
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {

	dadoAssinadoEmHexa := "0xa3d46b97492d362769420dbe0bcc87910579fb92e66c106d8c7fe029d00845882fc02d9149a63c9f9feee8e6e16f11edb5f7ae0cfb4e437ef1f5230c0336070c01"
	assinatura, err := hexutil.Decode(dadoAssinadoEmHexa)
	if err != nil {
		log.Fatalf("Erro ao decodificar assinatura para array de bytes %+v\n", err)
	}
	assinaturaSemRecoverID := assinatura[:len(assinatura)-1]

	chavePublicaEmHexa := "0x04f7270a93ba0c2ec6686797da050bd602293a3d6cc53d6b86758d44cae22813e9e864682e9e9d351bbfb65cadedf62d2687c78bf2fd9146be23172026f001ecdd"
	chavePublica, err := hexutil.Decode(chavePublicaEmHexa)
	if err != nil {
		log.Fatalf("Erro ao decodificar chave publica para array de bytes %+v\n", err)
	}

	dado := "Eu vou assinar esse texto aqui"
	hash := crypto.Keccak256Hash([]byte(dado))

	verificado := crypto.VerifySignature(chavePublica, hash.Bytes(), assinaturaSemRecoverID)
	log.Println("A assinatura esta verificada? ", verificado)

}

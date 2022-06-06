package goEncrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"runtime"
)

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile)
}

// EccEncrypt 使用公钥加密数据
func EccEncrypt(plainText, key []byte) (cryptText []byte, err error) {
	block, _ := pem.Decode(key)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	tempPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	publicKey1 := tempPublicKey.(*ecdsa.PublicKey)
	// Convert to the public key in the ecies package in the ethereum package
	publicKey := ImportECDSAPublic(publicKey1)
	crypttext, err := Encrypt(rand.Reader, publicKey, plainText, nil, nil)

	return crypttext, err

}

// EccDecrypt ECC解密数据
func EccDecrypt(cryptText, key []byte) (msg []byte, err error) {
	block, _ := pem.Decode(key)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	tempPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	// Convert to the private key in the ecies package in the ethereum package
	privateKey := ImportECDSA(tempPrivateKey)

	plainText, err := privateKey.Decrypt(cryptText, nil, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

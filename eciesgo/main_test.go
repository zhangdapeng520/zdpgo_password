package eciesgo

import (
	"log"
	"testing"
)

func TestMain111(t *testing.T) {
	data := "abc 123 张大鹏"

	// 生成key
	k, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	// 加密
	ciphertext, err := Encrypt(k.PublicKey, []byte(data))
	if err != nil {
		panic(err)
	}
	log.Printf("加密: %v\n", ciphertext)

	// 解密
	plaintext, err := Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	log.Printf("解密: %s\n", string(plaintext))
}

package aes

import (
	"bytes"
	"crypto/rand"
	"io"
)

// PKCS7Padding 补码
// AES加密数据块分组长度必须为128bit(byte[16])
// 密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

// PKCS7UnPadding 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

// 生成随机的nonce
func generateRandomNonce(noneLength int) []byte {
	nonce := make([]byte, noneLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	return nonce
}

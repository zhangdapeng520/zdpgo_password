package zdpgo_password

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type Aes struct {
	key string // AES加密的key
}

func NewAes(keys ...string) *Aes {
	// 获取key
	key := "_ZhangDapeng520%"
	if len(keys) > 0 {
		key = keys[0]
	}

	// 创建aes对象并返回
	a := Aes{
		key: key,
	}
	return &a
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func pkcs7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

//Encrypt AES加密，实现的是CBC模式
func (a *Aes) Encrypt(origData []byte) (string, error) {
	block, err := aes.NewCipher([]byte(a.key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData = pkcs7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, []byte(a.key)[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)

	// 将加密后的数据base64编码
	b64Data := Base64Encode(crypted)
	return b64Data, nil
}

//Decrypt AES解密
func (a *Aes) Decrypt(b64Data string) (string, error) {
	// 将密文base64解码
	crypted := Base64Decode(b64Data)
	block, err := aes.NewCipher([]byte(a.key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, []byte(a.key)[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, []byte(crypted))
	origData = pkcs7UnPadding(origData)
	return string(origData), nil
}

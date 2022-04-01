package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// AesCbc CBC模式下的AES加密对象
type AesCbc struct {
	Key string
}

func NewAesCbc(key string) *AesCbc {
	a := AesCbc{Key: key}

	return &a
}

func (ac *AesCbc) Encrypt(data []byte) ([]byte, error) {
	// 加密key的字节数组
	keyBytes := []byte(ac.Key)

	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(keyBytes)

	// 获取秘钥块的长度
	blockSize := block.BlockSize()

	// 补全码
	origData := PKCS7Padding(data, blockSize)

	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, keyBytes[:blockSize])

	// 创建数组
	cryted := make([]byte, len(origData))

	// 加密
	blockMode.CryptBlocks(cryted, origData)

	// 返回加密结果
	return cryted, nil
}

// EncryptString 加密字符串
func (ac *AesCbc) EncryptString(data string) (string, error) {
	// 加密数据，得到字节数组
	encryptBytes, err := ac.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 返回base64加密字符串
	return base64.StdEncoding.EncodeToString(encryptBytes), nil
}

// Decrypt 解密字节数组
func (ac *AesCbc) Decrypt(data []byte) ([]byte, error) {
	// key字节数组
	keyBytes := []byte(ac.Key)

	// 分组秘钥
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	// 获取秘钥块的长度
	blockSize := block.BlockSize()

	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, keyBytes[:blockSize])

	// 创建数组
	orig := make([]byte, len(data))

	// 解密
	blockMode.CryptBlocks(orig, data)

	// 去补全码
	orig = PKCS7UnPadding(orig)

	// 返回解密后的字节数组
	return orig, nil
}

// DecryptString 解密字符串
func (ac *AesCbc) DecryptString(b64Data string) (string, error) {
	// base64解码
	b64Bytes, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return "", err
	}

	// 解密字节数组
	decryptBytes, err := ac.Decrypt(b64Bytes)
	if err != nil {
		return "", err
	}

	// 返回字符串
	return string(decryptBytes), nil
}

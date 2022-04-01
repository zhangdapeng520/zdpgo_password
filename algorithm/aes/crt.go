package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type AesCrt struct {
	Key string
}

func NewAesCrt(key string) *AesCrt {
	return &AesCrt{Key: key}
}

func (ac *AesCrt) Encrypt(data []byte) ([]byte, error) {

	// 创建cipher.Block接口
	block, err := aes.NewCipher([]byte(ac.Key))
	if err != nil {
		return nil, err
	}

	// 创建分组模式，在crypto/cipher包中
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	// 加密/解密
	dst := make([]byte, len(data))
	stream.XORKeyStream(dst, data)

	// 返回加密/解密结果
	return dst, nil
}

func (ac *AesCrt) Decrypt(data []byte) ([]byte, error) {
	return ac.Encrypt(data)
}

func (ac *AesCrt) EncryptString(data string) (string, error) {
	// 得到加密的字节数组
	encryptBytes, err := ac.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 转换为base64字符串
	b64Data := base64.StdEncoding.EncodeToString(encryptBytes)

	// 返回base64字符串
	return b64Data, nil
}

func (ac *AesCrt) DecryptString(data string) (string, error) {
	// 解密base64字符串
	b64Bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	// 解密字节数组
	decrypt, err := ac.Decrypt(b64Bytes)
	if err != nil {
		return "", err
	}

	// 返回解密字符串
	return string(decrypt), nil
}

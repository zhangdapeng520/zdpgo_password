package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AesCfb CFB模式下的AES加密对象
type AesCfb struct {
	Key string
}

func NewAesCfb(key string) *AesCfb {
	a := AesCfb{Key: key}

	return &a
}

func (ac *AesCfb) Encrypt(data []byte) ([]byte, error) {
	// 创建cipher
	block, err := aes.NewCipher([]byte(ac.Key))
	if err != nil {
		return nil, err
	}

	// 准备加密数据
	encrypted := make([]byte, aes.BlockSize+len(data))
	iv := encrypted[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 加密
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], data)

	// 返回加密后的数据
	return encrypted, nil
}

// EncryptString 加密字符串
func (ac *AesCfb) EncryptString(data string) (string, error) {
	// 加密数据，得到字节数组
	encryptBytes, err := ac.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 返回base64加密字符串
	return base64.StdEncoding.EncodeToString(encryptBytes), nil
}

// Decrypt 解密字节数组
func (ac *AesCfb) Decrypt(data []byte) ([]byte, error) {
	// 创建cipher
	block, _ := aes.NewCipher([]byte(ac.Key))
	if len(data) < aes.BlockSize {
		return nil, errors.New("要加密的文本内容太短了")
	}

	// 获取加密数据
	iv := data[:aes.BlockSize]
	encrypted := data[aes.BlockSize:]

	// 解密
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)

	// 返回解密数据
	return encrypted, nil
}

// DecryptString 解密字符串
func (ac *AesCfb) DecryptString(b64Data string) (string, error) {
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

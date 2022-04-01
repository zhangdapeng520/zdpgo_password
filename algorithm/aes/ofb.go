package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AesOfb OFB模式下的AES加密对象
type AesOfb struct {
	Key string
}

func NewAesOfb(key string) *AesOfb {
	a := AesOfb{Key: key}

	return &a
}

func (ac *AesOfb) Encrypt(data []byte) ([]byte, error) {
	// 补码
	data = PKCS7Padding(data, aes.BlockSize)

	// 创建cipher
	block, _ := aes.NewCipher([]byte(ac.Key))

	// 创建加密对象
	out := make([]byte, aes.BlockSize+len(data))

	// 读取加密数据
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 加密
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(out[aes.BlockSize:], data)

	// 返回加密数据
	return out, nil
}

// EncryptString 加密字符串
func (ac *AesOfb) EncryptString(data string) (string, error) {
	// 加密数据，得到字节数组
	encryptBytes, err := ac.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 返回base64加密字符串
	return base64.StdEncoding.EncodeToString(encryptBytes), nil
}

// Decrypt 解密字节数组
func (ac *AesOfb) Decrypt(data []byte) ([]byte, error) {
	// 创建cipher
	block, _ := aes.NewCipher([]byte(ac.Key))

	// 读取解密数据
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("数据不是块大小的倍数")
	}

	// 解密数据
	out := make([]byte, len(data))
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(out, data)

	// 去码
	out = PKCS7UnPadding(out)

	// 返回解密数据
	return out, nil
}

// DecryptString 解密字符串
func (ac *AesOfb) DecryptString(b64Data string) (string, error) {
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

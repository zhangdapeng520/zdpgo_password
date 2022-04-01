package ecc

import (
	"encoding/base64"
	"errors"
	"github.com/zhangdapeng520/zdpgo_password/libs/eciesgo"
)

// Ecc ECC加密核心对象
type Ecc struct {
	PrivateKey *eciesgo.PrivateKey
	PublicKey  *eciesgo.PublicKey
}

// NewEcc 创建ECC加密对象的实例
func NewEcc() *Ecc {
	e := Ecc{}

	// 获取公钥和私钥
	k, err := eciesgo.GenerateKey()
	if err != nil {
		panic(err)
	}
	e.PrivateKey = k
	e.PublicKey = k.PublicKey

	// 返回
	return &e
}

// Encrypt ECC加密数据
func (e *Ecc) Encrypt(data []byte) ([]byte, error) {
	// 加密数据
	ciphertext, err := eciesgo.Encrypt(e.PublicKey, data)
	return ciphertext, err
}

// Decrypt ECC解密数据
func (e *Ecc) Decrypt(data []byte) ([]byte, error) {
	// 解密
	plaintext, err := eciesgo.Decrypt(e.PrivateKey, data)
	return plaintext, err
}

// EncryptString ECC加密字符串
func (e *Ecc) EncryptString(data string) (string, error) {
	// 执行加密
	encrypt, err := e.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 转换为base64字符串
	result := base64.StdEncoding.EncodeToString(encrypt)
	if result == "" {
		return "", errors.New("要解密的数据不存在")
	}

	// 正常返回
	return result, nil
}

// DecryptString ECC解密字符串
func (e *Ecc) DecryptString(data string) (string, error) {
	// 解析base64字符串
	bytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	// 执行解密
	decrypt, err := e.Decrypt(bytes)
	if err != nil {
		return "", err
	}

	// 转换为字符串
	return string(decrypt), nil
}

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
)

// AesGcm OFB模式下的AES加密对象
type AesGcm struct {
	Key string
}

func NewAesGcm(key string) *AesGcm {
	a := AesGcm{Key: key}

	return &a
}

func (ac *AesGcm) Encrypt(data []byte) ([]byte, error) {
	// 要加密的字符串
	plaintext := []byte(data)

	// 创建nonce
	nonce := generateRandomNonce(16)

	// 创建block
	block, err := aes.NewCipher([]byte(ac.Key))
	if err != nil {
		panic(err.Error())
	}

	// 创建gcm
	//aesGCM, err := cipher.NewGCM(block)
	aesGCM, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		panic(err.Error())
	}

	// 加密
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// 获取tag
	ciphertextWithTagLength := len(ciphertext)
	ciphertextWithoutTag, gcmTag := ciphertext[:(ciphertextWithTagLength-16)], ciphertext[(ciphertextWithTagLength-16):]

	// 转换为base64
	ciphertextWithoutTagBase64 := base64.StdEncoding.EncodeToString(ciphertextWithoutTag)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)
	gcmTagBase64 := base64.StdEncoding.EncodeToString(gcmTag)

	// 返回结果：data, nonce, tag
	// 拼接，使用--分割
	result := fmt.Sprintf("%s--%s--%s",
		ciphertextWithoutTagBase64, nonceBase64, gcmTagBase64)
	resultBytes := []byte(result)

	// 返回字节数组
	return resultBytes, nil
}

// EncryptString 加密字符串。返回的字符串是data, nonce, tag的base64编码，用--分割。
func (ac *AesGcm) EncryptString(data string) (string, error) {
	// 加密数据，得到字节数组
	encryptBytes, err := ac.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 返回base64加密字符串
	return base64.StdEncoding.EncodeToString(encryptBytes), nil
}

// Decrypt 解密字节数组
func (ac *AesGcm) Decrypt(data []byte) ([]byte, error) {
	// 将数据转换为字符串
	dataStr := string(data)
	fmt.Println("加密数据222：", dataStr)
	// 使用--进行切割
	dataArr := strings.Split(dataStr, "--")

	// 校验数据
	if len(dataArr) != 3 {
		return nil, errors.New("错误的加密信息，请检查传入的加密数据是否合法")
	}

	// 提取数据
	ciphertextWithoutTagBase64 := dataArr[0]
	nonceBase64 := dataArr[1]
	gcmTagBase64 := dataArr[2]

	// 将参数转换为字节数组
	dataBytes, _ := base64.StdEncoding.DecodeString(ciphertextWithoutTagBase64)
	keyBytes := []byte(ac.Key)
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonceBase64)
	tagBytes, _ := base64.StdEncoding.DecodeString(gcmTagBase64)

	// 解密
	ciphertextCompleteLength := len(dataBytes) + len(tagBytes)
	ciphertextComplete := make([]byte, ciphertextCompleteLength)
	ciphertextComplete = append(dataBytes[:], tagBytes[:]...)

	// 创建block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Println("aes.NewCipher 创建block失败：", err)
		return nil, err
	}

	// 创建gcm
	aesGCM, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		log.Println("cipher.NewGCM 创建gcm失败：", err)
		return nil, err
	}

	// 解密
	plaintext, err := aesGCM.Open(nil, nonceBytes, ciphertextComplete, nil)
	if err != nil {
		log.Println(" aesGCM.Open 解密失败：", err)
		return nil, err
	}

	// 转换为字符串返回
	return plaintext, nil
}

// DecryptString 解密字符串
func (ac *AesGcm) DecryptString(b64Data string) (string, error) {
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

package zdpgo_password

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

type Aes struct {
	config *AesConfig // aes的配置
}

func NewAes(config AesConfig) *Aes {
	a := Aes{}

	// 初始化配置
	if config.Key == "" {
		config.Key = "_ZhangDapeng520%"
	}
	if config.BlockSize == 0 {
		config.BlockSize = 16
	}
	a.config = &config

	// 返回
	return &a
}

func (a *Aes) padding(src []byte) []byte {
	//填充个数
	padding := aes.BlockSize - len(src)%aes.BlockSize
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, paddingText...)
}

func (a *Aes) unPadding(src []byte) []byte {
	size := len(src)
	return src[:(size - int(src[size-1]))]
}

// Encrypt 加密
func (a *Aes) Encrypt(src []byte) ([]byte, error) {
	//key只能是 16 24 32长度
	block, err := aes.NewCipher([]byte(a.config.Key))
	if err != nil {
		return nil, err
	}

	//padding
	src = a.padding(src)

	//返回加密结果
	encryptData := make([]byte, len(src))

	//存储每次加密的数据
	tmpData := make([]byte, a.config.BlockSize)

	//分组分块加密
	for index := 0; index < len(src); index += a.config.BlockSize {
		block.Encrypt(tmpData, src[index:index+a.config.BlockSize])
		copy(encryptData[index:index+a.config.BlockSize], tmpData)
	}
	return encryptData, nil
}

// Decrypt 解密
func (a *Aes) Decrypt(src []byte) ([]byte, error) {
	//key只能是 16 24 32长度
	block, err := aes.NewCipher([]byte(a.config.Key))
	if err != nil {
		return nil, err
	}
	//返回加密结果
	decryptData := make([]byte, len(src))
	//存储每次加密的数据
	tmpData := make([]byte, a.config.BlockSize)

	//分组分块加密
	for index := 0; index < len(src); index += a.config.BlockSize {
		block.Decrypt(tmpData, src[index:index+a.config.BlockSize])
		copy(decryptData[index:index+a.config.BlockSize], tmpData)
	}
	return a.unPadding(decryptData), nil
}

// EncryptString 加密字符串
func (a *Aes) EncryptString(src string) string {
	b, err := a.Encrypt([]byte(src))
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DecryptString AES解密字符串
func (a *Aes) DecryptString(src string) (string, error) {
	// 转换为base64编码
	decodeBytes, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}

	// 执行解密
	bytesData, err := a.Decrypt(decodeBytes)
	if err != nil {
		return "", err
	}

	// 返回数据
	return string(bytesData), nil
}

func generateRandomNonce() []byte {
	//nonce := make([]byte, 12)
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	return nonce
}

func (a *Aes) EncryptGcm(data, key string) (string, string, string) {
	// 要加密的字符串
	plaintext := []byte(data)

	// 创建nonce
	nonce := generateRandomNonce()

	// 创建block
	block, err := aes.NewCipher([]byte(key))
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
	fmt.Println("nonce length:", len(nonce))
	fmt.Println("gcmTag length:", len(gcmTag))
	ciphertextWithoutTagBase64 := base64.StdEncoding.EncodeToString(ciphertextWithoutTag)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)
	gcmTagBase64 := base64.StdEncoding.EncodeToString(gcmTag)

	// 返回结果：data, nonce, tag
	return ciphertextWithoutTagBase64, nonceBase64, gcmTagBase64
}

func (a *Aes) DecryptGcm(data, key, nonce, tag string) (string, error) {
	// 将参数转换为字节数组
	dataBytes, _ := base64.StdEncoding.DecodeString(data)
	keyBytes := []byte(key)
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonce)
	tagBytes, _ := base64.StdEncoding.DecodeString(tag)

	// 解密
	ciphertextCompleteLength := len(dataBytes) + len(tagBytes)
	ciphertextComplete := make([]byte, ciphertextCompleteLength)
	ciphertextComplete = append(dataBytes[:], tagBytes[:]...)

	// 创建block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Println("aes.NewCipher 创建block失败：", err)
		return "", err
	}

	// 创建gcm
	//aesGCM, err := cipher.NewGCM(block)
	aesGCM, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		log.Println("cipher.NewGCM 创建gcm失败：", err)
		return "", err
	}

	// 解密
	plaintext, err := aesGCM.Open(nil, nonceBytes, ciphertextComplete, nil)
	if err != nil {
		log.Println(" aesGCM.Open 解密失败：", err)
		return "", err
	}

	// 转换为字符串返回
	return string(plaintext), nil
}

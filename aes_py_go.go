package zdpgo_password

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
)

type AesPyGo struct {
	config *AesPyGoConfig // aes的配置
}

func NewAesPyGo(config AesPyGoConfig) *AesPyGo {
	apg := AesPyGo{}

	// 初始化配置
	if config.Key == "" {
		config.Key = "_ZhangDapeng520%"
	}
	if config.BlockSize == 0 {
		config.BlockSize = 16
	}
	apg.config = &config

	// 返回
	return &apg
}

func (apg *AesPyGo) padding(src []byte) []byte {
	//填充个数
	padding := aes.BlockSize - len(src)%aes.BlockSize
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, paddingText...)
}

func (apg *AesPyGo) unPadding(src []byte) []byte {
	size := len(src)
	return src[:(size - int(src[size-1]))]
}

// Encrypt 加密
func (apg *AesPyGo) Encrypt(src []byte) ([]byte, error) {
	//key只能是 16 24 32长度
	block, err := aes.NewCipher([]byte(apg.config.Key))
	if err != nil {
		return nil, err
	}
	//padding
	src = apg.padding(src)
	//返回加密结果
	encryptData := make([]byte, len(src))
	//存储每次加密的数据
	tmpData := make([]byte, apg.config.BlockSize)

	//分组分块加密
	for index := 0; index < len(src); index += apg.config.BlockSize {
		block.Encrypt(tmpData, src[index:index+apg.config.BlockSize])
		copy(encryptData[index:index+apg.config.BlockSize], tmpData)
	}
	return encryptData, nil
}

// Decrypt 解密
func (apg *AesPyGo) Decrypt(src []byte) ([]byte, error) {
	//key只能是 16 24 32长度
	block, err := aes.NewCipher([]byte(apg.config.Key))
	if err != nil {
		return nil, err
	}
	//返回加密结果
	decryptData := make([]byte, len(src))
	//存储每次加密的数据
	tmpData := make([]byte, apg.config.BlockSize)

	//分组分块加密
	for index := 0; index < len(src); index += apg.config.BlockSize {
		block.Decrypt(tmpData, src[index:index+apg.config.BlockSize])
		copy(decryptData[index:index+apg.config.BlockSize], tmpData)
	}
	return apg.unPadding(decryptData), nil
}

// EncryptString 加密字符串
func (apg *AesPyGo) EncryptString(src string) string {
	b, err := apg.Encrypt([]byte(src))
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DecryptString AES解密字符串
func (apg *AesPyGo) DecryptString(src string) (string, error) {
	// 转换为base64编码
	decodeBytes, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}

	// 执行解密
	bytesData, err := apg.Decrypt(decodeBytes)
	if err != nil {
		return "", err
	}

	// 返回数据
	return string(bytesData), nil
}

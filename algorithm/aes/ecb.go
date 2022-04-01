package aes

import (
	"crypto/aes"
	"encoding/base64"
)

// AesEcb ecb模式下的AES加密对象
type AesEcb struct {
	Key string // 加密的key
}

// NewAesEcb 创建ecb模式下的aes加密对象
func NewAesEcb(key string) *AesEcb {
	return &AesEcb{Key: key}
}

// 生成ECB加密的Key，保证key的长度用于是16个
func generateEcbKey(key []byte) (genKey []byte) {
	// 创建16位的字节数组
	genKey = make([]byte, 16)

	// 将原本的key复制过来
	copy(genKey, key)

	// 生成key的算法
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}

	// 返回生成的key
	return genKey
}

// Encrypt 加密字节数组
func (ae *AesEcb) Encrypt(data []byte) ([]byte, error) {
	// 创建cipher
	cipher, _ := aes.NewCipher(generateEcbKey([]byte(ae.Key)))

	// 获取块的大小
	length := (len(data) + aes.BlockSize) / aes.BlockSize

	// 创建明文字节数组
	plain := make([]byte, length*aes.BlockSize)

	// 复制明文
	copy(plain, data)

	// 对齐
	pad := byte(len(plain) - len(data))
	for i := len(data); i < len(plain); i++ {
		plain[i] = pad
	}

	// 创建加密数组
	encrypted := make([]byte, len(plain))

	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(data); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	// 返回加密数据
	return encrypted, nil
}

// Decrypt 使用ECB模式的AES解密字节数组
func (ae *AesEcb) Decrypt(data []byte) ([]byte, error) {
	// 创建cipher
	cipher, _ := aes.NewCipher(generateEcbKey([]byte(ae.Key)))

	// 创建解密数组
	decrypted := make([]byte, len(data))

	// 分组分块解密
	for bs, be := 0, cipher.BlockSize(); bs < len(data); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	// 计算要去除的长度
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	// 返回去除无效数据后的真实解密数据
	return decrypted[:trim], nil
}

// EncryptString 使用ECB模式下的AES加密方法加密字符串
func (ae *AesEcb) EncryptString(data string) (string, error) {
	// 加密字符串，得到加密的字节数组
	encrypt, err := ae.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 将字节数组转换为base64字符串
	b64Data := base64.StdEncoding.EncodeToString(encrypt)

	// 返回加密后的base64字符串
	return b64Data, nil
}

// DecryptString 使用ECB模式下的AES解密方法解密字符串
func (ae *AesEcb) DecryptString(data string) (string, error) {
	// 对字符串做base64解码，得到字节数组
	decodeBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	// 解密字节数组
	decryptBytes, err := ae.Decrypt(decodeBytes)
	if err != nil {
		return "", err
	}

	// 将解密的字节数组转换为字符串返回
	return string(decryptBytes), nil
}

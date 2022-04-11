package hash

import (
	"crypto/sha512"
	"encoding/hex"
)

// Sha512 sha512加密核心对象
type Sha512 struct {
	Key string // 加密的key
}

// NewSha512 创建sha512的加密对象
func NewSha512(key string) *Sha512 {
	return &Sha512{Key: key}
}

// EncryptString 加密字符串
func (sh *Sha512) EncryptString(data string) (string, error) {
	// 创建sha512对象
	s := sha512.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(sh.Key))), nil
}

// Encrypt 加密字节数组
func (sh *Sha512) Encrypt(data []byte) ([]byte, error) {
	// 创建sha512对象
	s := sha512.New()

	// 对数据进行加密
	s.Write(data)

	// 返回加密数据
	return s.Sum([]byte(sh.Key)), nil
}

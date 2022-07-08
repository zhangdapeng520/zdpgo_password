package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256 sha256加密核心对象
type Sha256 struct {
	Key string // 加密的key
}

// NewSha256 创建sha256的加密对象
func NewSha256(key string) *Sha256 {
	return &Sha256{Key: key}
}

// EncryptString 加密字符串
func (sh *Sha256) EncryptString(data string) (string, error) {
	// 创建sha256对象
	s := sha256.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(sh.Key))), nil
}

// Encrypt 加密字节数组
func (sh *Sha256) Encrypt(data []byte) ([]byte, error) {
	// 创建sha256对象
	s := sha256.New()

	// 对数据进行加密
	s.Write(data)

	// 返回加密数据
	return s.Sum([]byte(sh.Key)), nil
}

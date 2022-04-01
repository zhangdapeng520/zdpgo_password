package hash

import (
	"crypto/sha1"
	"encoding/hex"
)

// Sha1 sha1加密核心对象
type Sha1 struct {
	Key string // 加密的key
}

// NewSha1 创建sha1的加密对象
func NewSha1(key string) *Sha1 {
	return &Sha1{Key: key}
}

// EncryptString 加密字符串
func (sh *Sha1) EncryptString(data string) (string, error) {
	// 创建sha1对象
	s := sha1.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(sh.Key))), nil
}

// Encrypt 加密字节数组
func (sh *Sha1) Encrypt(data []byte) ([]byte, error) {
	// 创建sha1对象
	s := sha1.New()

	// 对数据进行加密
	s.Write(data)

	// 返回加密数据
	return s.Sum([]byte(sh.Key)), nil
}

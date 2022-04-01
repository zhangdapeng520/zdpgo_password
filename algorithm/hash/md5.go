package hash

import (
	"crypto/md5"
	"encoding/hex"
)

// MD5信息摘要算法是一种被广泛使用的密码散列函数，可以产生出一个128位（16进制，32个字符）的散列值（hash value），用于确保信息传输完整一致。

// Md5 md5加密对象
type Md5 struct {
}

// NewMd5 创建md5加密对象的实例
func NewMd5() *Md5 {
	return &Md5{}
}

// EncryptString 加密字符串
func (m *Md5) EncryptString(data string) (string, error) {
	// 创建md5加密对象
	h := md5.New()

	// 加密数据
	h.Write([]byte(data))

	// 返回加密后的数据
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Encrypt 加密字节数组
func (m *Md5) Encrypt(data []byte) ([]byte, error) {
	// 创建md5加密对象
	h := md5.New()

	// 加密数据
	h.Write(data)

	// 返回加密后的数据
	return h.Sum(nil), nil
}

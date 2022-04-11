package hash

import (
	"crypto/md5"
	"encoding/hex"
)

// MD5信息摘要算法是一种被广泛使用的密码散列函数，可以产生出一个128位（16进制，32个字符）的散列值（hash value），用于确保信息传输完整一致。

// Md5 md5加密对象
type Md5 struct {
	Key string // 加密的key
}

// NewMd5 创建md5加密对象的实例
func NewMd5(key string) *Md5 {
	return &Md5{Key: key}
}

// EncryptString 加密字符串
func (m *Md5) EncryptString(data string) (string, error) {
	// 创建md5加密对象
	h := md5.New()

	// 加密数据
	h.Write([]byte(data))

	// 返回加密后的数据
	return hex.EncodeToString(h.Sum([]byte(m.Key))), nil
}

// Encrypt 加密字节数组
func (m *Md5) Encrypt(data []byte) ([]byte, error) {
	// 创建md5加密对象
	h := md5.New()

	// 加密数据
	h.Write(data)

	// 返回加密后的数据
	return h.Sum([]byte(m.Key)), nil
}

// EncryptNoKey 不使用任何Key加密字节数组
// @param data 要加密的数据
// 返回16进制的加密字符串
func (m *Md5) EncryptNoKey(data []byte) string {
	h := md5.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// CheckNoKey 检查加密字符串是否正确
// @param srcStr md5加密后的16进制字符串
// @param descData 要检查的加密前的数据
// 返回一个布尔值
func (m *Md5) CheckNoKey(srcStr string, descData []byte) bool {
	t := m.EncryptNoKey(descData)
	return t == srcStr
}

// EncryptStringNoKey 不使用任何Key加密字节数组
// @param data 要加密的字符串
// 返回16进制的加密字符串
func (m *Md5) EncryptStringNoKey(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// CheckStringNoKey 检查加密字符串是否正确
// @param srcStr md5加密后的16进制字符串
// @param descData 要检查的加密前的字符串
// 返回一个布尔值
func (m *Md5) CheckStringNoKey(srcStr string, descData string) bool {
	t := m.EncryptNoKey([]byte(descData))
	return t == srcStr
}

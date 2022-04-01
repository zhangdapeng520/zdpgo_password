package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
)

// HMAC是密钥相关的哈希运算消息认证码（Hash-based Message Authentication Code）的缩写，
// 它通过一个标准算法，在计算哈希的过程中，把key混入计算过程中。
// 和我们自定义的加salt算法不同，Hmac算法针对所有哈希算法都通用，无论是MD5还是SHA-1。采用Hmac替代我们自己的salt算法，可以使程序算法更标准化，也更安全。

// Hmac hmac加密算法核心类
type Hmac struct {
	Key       string // 加密的key
	Algorithm string // 计算算法
}

// NewHmac 创建hmac加密对象
func NewHmac(key, algorithm string) *Hmac {
	return &Hmac{
		Key:       key,
		Algorithm: algorithm,
	}
}

// Encrypt 加密字节数组
func (h *Hmac) Encrypt(data []byte) ([]byte, error) {
	// 创建对应的md5哈希加密算法
	var hs hash.Hash

	// 根据配置实例化加密对象
	switch h.Algorithm {
	case "md5":
		hs = hmac.New(md5.New, []byte(h.Key))
	case "sha1":
		hs = hmac.New(sha1.New, []byte(h.Key))
	case "sha256":
		hs = hmac.New(sha256.New, []byte(h.Key))
	case "sha512":
		hs = hmac.New(sha512.New, []byte(h.Key))
	default:
		hs = hmac.New(sha256.New, []byte(h.Key))
	}

	// 对数据进行加密
	hs.Write(data)

	// 返回加密结果
	return hs.Sum([]byte("")), nil
}

// EncryptString 加密字符串
func (h *Hmac) EncryptString(data string) (string, error) {
	result, err := h.Encrypt([]byte(data))
	return hex.EncodeToString(result), err
}

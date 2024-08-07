package zdpgo_password

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256EncryptString 加密字符串
func Sha256EncryptString(data, salt string) (string, error) {
	// 创建sha256对象
	s := sha256.New()

	// 对数据进行加密
	s.Write([]byte(data))

	// 返回加密数据
	return hex.EncodeToString(s.Sum([]byte(salt))), nil
}

// Sha256ValidateString 校验字符串是否符合加密后的要求
func Sha256ValidateString(data, salt, encrypted string) bool {
	dataEncrypted, err := Sha256EncryptString(data, salt)
	if err != nil {
		return false
	}
	return encrypted == dataEncrypted
}
